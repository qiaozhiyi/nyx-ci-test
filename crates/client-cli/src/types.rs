//! Wire types (mirror the REST API) + domain models for parsed agent output.

use serde::Deserialize;

// ---- REST wire types (same shapes as client-ui/bridge.rs & server) ----

/// One beacon session, as returned by `GET /api/sessions`. Fields mirror the
/// REST shape 1:1; some aren't rendered yet (pid) but are kept so the struct
/// stays a faithful wire type.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionView {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    #[serde(default)]
    pub is_admin: u8,
    #[serde(default)]
    pub pending: usize,
    #[serde(default)]
    pub beacon_id: u32,
    #[serde(default)]
    pub arch: u8,
    #[serde(default)]
    #[allow(dead_code)]
    pub pid: u32,
}

#[derive(Deserialize)]
pub struct TaskAck {
    pub task_id: u64,
    #[serde(default)]
    pub chan: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResultView {
    pub task_id: u64,
    pub kind: String,
    pub text: String,
    #[serde(default)]
    pub data_hex: Option<String>,
    #[serde(default)]
    pub seq: Option<u32>,
    #[serde(default)]
    pub eof: Option<u8>,
}

// ---- domain models (parsed agent output) ----

/// One row of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified: String,
}

/// One row of a process listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub user: String,
}

/// One dumped credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredEntry {
    pub source: String,
    pub principal: String,
    pub kind: CredKind,
    pub secret: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredKind {
    Hash,
    Password,
    Ticket,
    Key,
}

impl CredKind {
    pub fn label(self) -> &'static str {
        match self {
            CredKind::Hash => "hash",
            CredKind::Password => "password",
            CredKind::Ticket => "ticket",
            CredKind::Key => "key",
        }
    }
}

/// Architecture tag from the SessionInfo `arch` byte (matches the GUI widget).
pub fn arch_str(a: u8) -> &'static str {
    match a {
        0 => "?",
        1 => "x86",
        2 => "x64",
        3 => "arm",
        4 => "arm64",
        _ => "?",
    }
}
