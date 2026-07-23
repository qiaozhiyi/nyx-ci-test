//! Events the team server emits to the scripting bus.

/// Fired when an implant checks in for the first time.
#[derive(Debug, Clone)]
pub struct SessionNew {
    pub session_id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub is_admin: bool,
}

/// Coarse classification of a task result, for routing in scripts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultKind {
    Output,
    Ok,
    Err,
    FileChunk,
    /// BOF output, channel data, or any future response kind.
    Other,
}

/// Fired when the server receives a task result from an implant.
#[derive(Debug, Clone)]
pub struct ResultReceived {
    pub session_id: String,
    pub task_id: u64,
    pub kind: ResultKind,
    pub summary: String,
}

/// Fired when a session tears down.
#[derive(Debug, Clone)]
pub struct SessionExit {
    pub session_id: String,
}
