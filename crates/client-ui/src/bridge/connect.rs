//! Connect-attempt lifecycle: stage tracking, the overlay-driving snapshot
//! pushes, and the 20s wedged-attempt timeout.
//!
//! A connect attempt is the span between `Cmd::Connect` arriving and the next
//! `fetch_sessions` resolution (Ok → Done, Err → Failed). The UI's connect
//! overlay is visible exactly while [`ConnectState::connecting`] is true; the
//! stage drives the step-tip line under the progress bar.

use std::time::{Duration, Instant};

use makepad_widgets::makepad_platform::makepad_network::ui_signal::ToUISender;

use super::{log_push, take_snapshot, ConnectStage, Snapshot, WorkerState};

/// State of the (at most one) in-flight connect attempt.
#[derive(Default)]
pub(crate) struct ConnectState {
    /// True while a `Cmd::Connect` attempt is in flight.
    pub connecting: bool,
    /// The real connection stage currently in flight (or the last one reached).
    pub stage: ConnectStage,
    /// Start time of the in-flight attempt; drives the wedged-attempt timeout.
    pub attempt_time: Option<Instant>,
}

impl WorkerState {
    /// 20s timeout: if a connect attempt never resolves (dropped packets, no
    /// RST), give up so the overlay can't get stuck open.
    pub(super) fn check_connect_timeout(&mut self, to_ui: &ToUISender<Snapshot>) {
        if !self.connect.connecting {
            return;
        }
        if let Some(t0) = self.connect.attempt_time {
            if t0.elapsed() > Duration::from_secs(20) {
                self.connect.connecting = false;
                self.connect.stage = ConnectStage::Failed;
                self.connect.attempt_time = None;
                log_push(&mut self.log_buf, "! connect: timed out");
                let _ = to_ui.send(take_snapshot(
                    &mut self.log_buf,
                    false,
                    &[],
                    &mut self.bof_updates,
                    &mut self.console_lines,
                    self.connect.connecting,
                    self.connect.stage,
                ));
            }
        }
    }

    /// Begin a connect attempt: record the target server, mark the attempt
    /// in-flight at stage `Resolving`, and push the snapshot that opens the
    /// connect overlay.
    pub(super) fn begin_connect(
        &mut self,
        server: String,
        password: Option<String>,
        to_ui: &ToUISender<Snapshot>,
    ) {
        log_push(&mut self.log_buf, format!("connecting to {server} …"));
        self.server = Some((server, password));
        self.connect.connecting = true;
        self.connect.stage = ConnectStage::Resolving;
        self.connect.attempt_time = Some(Instant::now());
        let _ = to_ui.send(take_snapshot(
            &mut self.log_buf,
            false,
            &[],
            &mut self.bof_updates,
            &mut self.console_lines,
            self.connect.connecting,
            self.connect.stage,
        ));
    }

    /// A successful `fetch_sessions` ends the attempt at stage `Done`.
    pub(super) fn settle_connect_ok(&mut self) {
        if self.connect.connecting {
            self.connect.connecting = false;
            self.connect.stage = ConnectStage::Done;
            self.connect.attempt_time = None;
        }
    }

    /// A failed `fetch_sessions` ends the attempt at stage `Failed`.
    pub(super) fn settle_connect_err(&mut self) {
        if self.connect.connecting {
            self.connect.connecting = false;
            self.connect.stage = ConnectStage::Failed;
            self.connect.attempt_time = None;
        }
    }
}
