//! Example built-in hooks — small, composable, and the pattern a Lua/Rune
//! binding will follow.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::hook::{Event, Hook};

/// Records a one-line summary of every event. Handy for logging/debugging and
/// for tests that need to assert which events fired.
pub struct LogHook {
    pub records: Arc<Mutex<Vec<String>>>,
}

impl LogHook {
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Default for LogHook {
    fn default() -> Self {
        Self::new()
    }
}

impl Hook for LogHook {
    fn name(&self) -> &str {
        "log"
    }
    fn on_event(&self, event: &Event) {
        let line = match event {
            Event::SessionNew(s) => format!("session_new: {}@{}", s.username, s.hostname),
            Event::ResultReceived(r) => {
                format!(
                    "result: {}#{} {:?} {}",
                    r.session_id, r.task_id, r.kind, r.summary
                )
            }
            Event::SessionExit(s) => format!("session_exit: {}", s.session_id),
        };
        self.records.lock().unwrap().push(line);
    }
}

/// Fires only on the first `SessionNew` for each session id — the foundation
/// of "first blood"-style automation (auto-run a TTP the instant a new box,
/// especially an admin box, pops).
pub struct FirstBloodHook {
    seen: Mutex<HashSet<String>>,
    pub records: Arc<Mutex<Vec<String>>>,
}

impl FirstBloodHook {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            records: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Default for FirstBloodHook {
    fn default() -> Self {
        Self::new()
    }
}

impl Hook for FirstBloodHook {
    fn name(&self) -> &str {
        "first_blood"
    }
    fn on_event(&self, event: &Event) {
        if let Event::SessionNew(s) = event {
            // `seen` lock released at the end of this statement, before the
            // records lock below — no nested locking.
            let is_first = self.seen.lock().unwrap().insert(s.session_id.clone());
            if is_first {
                self.records
                    .lock()
                    .unwrap()
                    .push(format!("first blood: {}@{}", s.username, s.hostname));
            }
        }
    }
}
