//! Credential-vault command arms: fetch (list to the event log), add, delete.

use super::rest;
use super::{authed, log_push, Cmd, WorkerState};

impl WorkerState {
    /// Dispatch one credential-vault command. All three arms are
    /// server-control API calls (not session tasks) and log
    /// `"! not connected"` when the worker has no server (pre-split behavior).
    pub(super) async fn dispatch_creds(&mut self, client: &reqwest::Client, cmd: Cmd) {
        let server = self.server.clone();
        match cmd {
            Cmd::FetchCreds { reveal } => {
                let Some((srv, token)) = server.as_ref() else {
                    return;
                };
                let url = if reveal {
                    format!("{srv}/api/creds?reveal=1")
                } else {
                    format!("{srv}/api/creds")
                };
                match authed(client.get(&url), token).send().await {
                    Ok(resp) => match resp.json::<Vec<serde_json::Value>>().await {
                        Ok(rows) => {
                            log_push(
                                &mut self.log_buf,
                                format!("server creds: {} record(s)", rows.len()),
                            );
                            for r in rows.iter().take(50) {
                                let realm =
                                    r.get("realm").and_then(|v| v.as_str()).unwrap_or("");
                                let user = r.get("user").and_then(|v| v.as_str()).unwrap_or("");
                                let kind =
                                    r.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
                                let secret =
                                    r.get("secret").and_then(|v| v.as_str()).unwrap_or("");
                                log_push(
                                    &mut self.log_buf,
                                    format!("  {kind:8} {realm}\\{user}: {secret}"),
                                );
                            }
                            if rows.len() > 50 {
                                log_push(
                                    &mut self.log_buf,
                                    format!(
                                        "  ... ({} more, use CLI /creds sync for full)",
                                        rows.len() - 50
                                    ),
                                );
                            }
                        }
                        Err(e) => log_push(&mut self.log_buf, format!("! creds parse: {e}")),
                    },
                    Err(e) => log_push(&mut self.log_buf, format!("! creds fetch: {e}")),
                }
            }
            Cmd::CredAdd {
                realm,
                user,
                kind,
                secret,
            } => {
                let Some((srv, token)) = server.as_ref() else {
                    log_push(&mut self.log_buf, "! not connected");
                    return;
                };
                match rest::cred_add(client, srv, &realm, &user, &kind, &secret, token).await {
                    Ok(()) => {
                        log_push(&mut self.log_buf, format!("cred added: {kind} {realm}\\{user}"))
                    }
                    Err(e) => log_push(&mut self.log_buf, format!("! cred add: {e}")),
                }
            }
            Cmd::CredDelete { realm, user, kind } => {
                let Some((srv, token)) = server.as_ref() else {
                    log_push(&mut self.log_buf, "! not connected");
                    return;
                };
                match rest::cred_delete(client, srv, &realm, &user, &kind, token).await {
                    Ok(true) => log_push(
                        &mut self.log_buf,
                        format!("cred deleted: {kind} {realm}\\{user}"),
                    ),
                    Ok(false) => log_push(
                        &mut self.log_buf,
                        format!("cred delete: no match {kind} {realm}\\{user}"),
                    ),
                    Err(e) => log_push(&mut self.log_buf, format!("! cred delete: {e}")),
                }
            }
            _ => unreachable!("dispatch_creds called with a non-cred command"),
        }
    }
}
