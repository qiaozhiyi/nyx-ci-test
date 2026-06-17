//! Nyx operator GUI — a pure-Rust **egui** desktop client. No Node/JS/HTML: it
//! is a single Rust binary that talks to the team server's REST API (the same
//! surface as `nyx-cli`). Left panel = live sessions; centre = a console that
//! tasks `shell` commands and prints the output. Extend as needed (upload/
//! download, BOF, profile view).
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

/// Background -> UI message.
enum Msg {
    Sessions(Vec<SessionView>),
    Line(String),
}

struct App {
    server: String,
    sessions: Vec<SessionView>,
    selected: Option<String>,
    rx: Receiver<Msg>,
    tx: Sender<Msg>,
    shell_input: String,
    log: Vec<String>,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = mpsc::channel();
        let server =
            std::env::var("NYX_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8443".to_string());

        // Background: refresh the session list every second + request a repaint.
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
            log: vec!["Nyx client ready. Select a session, then run `shell`.".into()],
        }
    }

    fn run_shell(&mut self, ctx: &egui::Context) {
        let Some(sid) = self.selected.clone() else {
            self.log.push("! select a session first".into());
            return;
        };
        let cmd = self.shell_input.trim().to_string();
        if cmd.is_empty() {
            return;
        }
        self.shell_input.clear();
        self.log.push(format!("$ {cmd}"));
        let (srv, tx, ctx) = (self.server.clone(), self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let line = match enqueue_shell(&srv, &sid, &cmd) {
                Ok(tid) => match poll_result(&srv, &sid, tid) {
                    Ok(Some(out)) => out,
                    Ok(None) => "[no output within timeout]".into(),
                    Err(e) => format!("! {e}"),
                },
                Err(e) => format!("! {e}"),
            };
            let _ = tx.send(Msg::Line(line));
            ctx.request_repaint();
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain background messages.
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Sessions(s) => {
                    // Keep selection valid.
                    if let Some(id) = &self.selected {
                        if !s.iter().any(|x| &x.id == id) {
                            self.selected = None;
                        }
                    }
                    self.sessions = s;
                }
                Msg::Line(l) => self.log.push(l),
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
                ui.heading("Console");
                ui.label(
                    self.selected
                        .as_ref()
                        .map(|s| format!("({})", &s[..8.min(s.len())]))
                        .unwrap_or_default(),
                );
            });
            ui.separator();
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.log {
                        ui.label(line);
                    }
                });
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("nyx>");
                let resp = ui.text_edit_singleline(&mut self.shell_input);
                let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Run").clicked() || enter {
                    self.run_shell(ctx);
                }
            });
        });
    }
}

fn fetch_sessions(server: &str) -> anyhow::Result<Vec<SessionView>> {
    Ok(ureq::get(&format!("{server}/api/sessions")).call()?.into_json()?)
}

fn enqueue_shell(server: &str, session: &str, args: &str) -> anyhow::Result<u64> {
    let body = serde_json::json!({ "session": session, "command": { "type": "shell", "args": args } });
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
            let text = match r.kind.as_str() {
                "output" => r.text,
                "ok" => String::new(),
                "error" => format!("[error] {}", r.text),
                other => format!("[{other}] {}", r.text),
            };
            return Ok(Some(text));
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn main() -> eframe::Result<()> {
    let opts = eframe::NativeOptions::default();
    eframe::run_native(
        "Nyx",
        opts,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
