//! File-domain command arms: remote `ls` (parsed into the FileTree), up/download,
//! file ops (cd/mkdir/rm/mv/cp), and drive info.

use super::poll::TaskKind;
use super::{short, Cmd, WorkerState};

impl WorkerState {
    /// Dispatch one file-domain command. Shares the [`super::dispatch::Enqueue`]
    /// pattern; every arm skips silently when disconnected (matches the
    /// pre-split bridge).
    pub(super) async fn dispatch_files(&mut self, client: &reqwest::Client, cmd: Cmd) {
        let server = self.server.clone();
        let Some(server) = server.as_ref() else {
            return;
        };
        match cmd {
            Cmd::Ls { session, args } => {
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "ls",
                        serde_json::json!({ "type": "shell", "args": args }),
                        TaskKind::Ls,
                        |tid| format!("[{}] ls → task {}", short(&session), tid),
                    )
                    .await;
            }
            Cmd::Upload {
                session,
                name,
                data_hex,
            } => {
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "upload",
                        serde_json::json!({ "type": "upload", "name": name, "data_hex": data_hex }),
                        TaskKind::Generic("upload".to_string()),
                        |tid| format!("[{}] upload {} → task {}", short(&session), name, tid),
                    )
                    .await;
            }
            Cmd::Download { session, path } => {
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "download",
                        serde_json::json!({ "type": "download", "path": path }),
                        TaskKind::Generic("download".to_string()),
                        |tid| format!("[{}] download {} → task {}", short(&session), path, tid),
                    )
                    .await;
            }
            Cmd::FileOp {
                session,
                op,
                path,
                dest,
            } => {
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "fileop",
                        serde_json::json!({ "type": "fileop", "op": op, "path": path, "dest": dest }),
                        TaskKind::Generic(op.clone()),
                        |tid| format!("[{}] {} {} → task {}", short(&session), op, path, tid),
                    )
                    .await;
            }
            Cmd::Driveinfo { session } => {
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "driveinfo",
                        serde_json::json!({ "type": "driveinfo" }),
                        TaskKind::Generic("driveinfo".to_string()),
                        |tid| format!("[{}] driveinfo → task {}", short(&session), tid),
                    )
                    .await;
            }
            _ => unreachable!("dispatch_files called with a non-file command"),
        }
    }
}
