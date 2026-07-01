//! Wire types (mirror the REST API) + domain models for parsed agent output.
//!
//! REST view types (`SessionView`/`TaskAck`/`ResultView`) and the `arch` map are
//! re-exported from the shared `nyx_rest` crate, so this client can't drift from
//! client-ui or the server (the prior copies silently dropped `age_secs`/`ja3`/
//! `ja4` and disagreed on the `arch` byte mapping). Domain models for parsed
//! agent output stay here.

// ---- REST wire types + arch map (shared — see crates/rest) ---------------
// Re-exported so the historical `crate::types::SessionView` / `arch_str` paths
// keep resolving with zero call-site churn.
/// Re-export of the shared, protocol-correct arch mapping under this crate's
/// historical name so existing call sites keep working.
pub use nyx_rest::arch_name as arch_str;
pub use nyx_rest::{ResultView, SessionView, TaskAck};

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

// Architecture tag from the `arch` wire byte — re-exported from `nyx_rest`
// (see the `arch_str` alias above) so there is one protocol-correct mapping.
