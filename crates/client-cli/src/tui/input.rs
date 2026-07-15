//! Pure input-classification and interaction logic.
//!
//! Everything here is a free function or data type with no UI/runtime state.
//! This keeps the decision logic unit-testable independently of the TUI event
//! loop. `mod.rs` re-exports these symbols so existing call sites don't change.

// ---- slash-command catalogue ----------------------------------------------

/// One entry in the `/` menu.
pub(crate) struct MetaCmd {
    pub name: &'static str,      // e.g. "/ls"
    pub args_hint: &'static str, // e.g. "[path]"
    pub help: &'static str,      // short description
    pub icon: &'static str,      // cyber 风格图标，渲染在命令名前
}

pub(crate) const META_COMMANDS: &[MetaCmd] = &[
    MetaCmd {
        name: "/sessions",
        args_hint: "[filter]",
        help: "list beacons / switch",
        icon: "◉",
    },
    MetaCmd {
        name: "/connect",
        args_hint: "<url> [token]",
        help: "switch team server",
        icon: "⇄",
    },
    MetaCmd {
        name: "/use",
        args_hint: "<id>",
        help: "select beacon by id prefix",
        icon: "▣",
    },
    MetaCmd {
        name: "/info",
        args_hint: "",
        help: "full details of current beacon",
        icon: "ℹ",
    },
    MetaCmd {
        name: "/rename",
        args_hint: "<id> <name>",
        help: "alias a beacon",
        icon: "✎",
    },
    MetaCmd {
        name: "/tag",
        args_hint: "<id> <tag>",
        help: "tag a beacon",
        icon: "▸",
    },
    MetaCmd {
        name: "/untag",
        args_hint: "<id> <tag>",
        help: "remove a tag",
        icon: "▹",
    },
    MetaCmd {
        name: "/star",
        args_hint: "<id>",
        help: "toggle favorite",
        icon: "★",
    },
    MetaCmd {
        name: "/note",
        args_hint: "<id> <text>",
        help: "annotate a beacon",
        icon: "✑",
    },
    MetaCmd {
        name: "/alias",
        args_hint: "add|rm|list",
        help: "command aliases",
        icon: "⟜",
    },
    MetaCmd {
        name: "/topo",
        args_hint: "",
        help: "topology graph",
        icon: "▨",
    },
    MetaCmd {
        name: "/ls",
        args_hint: "[path]",
        help: "list files (parsed)",
        icon: "☰",
    },
    MetaCmd {
        name: "/cd",
        args_hint: "<path>",
        help: "change dir",
        icon: "›",
    },
    MetaCmd {
        name: "/mkdir",
        args_hint: "<path>",
        help: "make directory",
        icon: "⊞",
    },
    MetaCmd {
        name: "/rm",
        args_hint: "<path>",
        help: "remove file/dir",
        icon: "✕",
    },
    MetaCmd {
        name: "/mv",
        args_hint: "<src> <dst>",
        help: "move/rename",
        icon: "⇄",
    },
    MetaCmd {
        name: "/cp",
        args_hint: "<src> <dst>",
        help: "copy",
        icon: "⧉",
    },
    MetaCmd {
        name: "/ps",
        args_hint: "",
        help: "list processes (parsed)",
        icon: "⚔",
    },
    MetaCmd {
        name: "/creds",
        args_hint: "[list|find|sync|export]",
        help: "credentials vault",
        icon: "⚿",
    },
    MetaCmd {
        name: "/creds add",
        args_hint: "<realm> <user> <kind> <secret>",
        help: "add credential to server vault",
        icon: "⚿",
    },
    MetaCmd {
        name: "/creds del",
        args_hint: "<realm> <user> <kind>",
        help: "delete credential from server vault",
        icon: "⚿",
    },
    MetaCmd {
        name: "/audit",
        args_hint: "[operator <n>] [action <a>] [limit <n>]",
        help: "server action audit log",
        icon: "⛒",
    },
    MetaCmd {
        name: "/audit verify",
        args_hint: "",
        help: "verify audit log hash chain",
        icon: "⛒",
    },
    MetaCmd {
        name: "/tasks",
        args_hint: "",
        help: "queued (undelivered) tasks for current beacon",
        icon: "☐",
    },
    MetaCmd {
        name: "/profile",
        args_hint: "",
        help: "fetch active C2 profile summary",
        icon: "⚙",
    },
    MetaCmd {
        name: "/bof",
        args_hint: "<file> [args]",
        help: "run a BOF object",
        icon: "▲",
    },
    MetaCmd {
        name: "/upload",
        args_hint: "<local> <remote>",
        help: "upload a file",
        icon: "↑",
    },
    MetaCmd {
        name: "/download",
        args_hint: "<remote> [local]",
        help: "download a file",
        icon: "↓",
    },
    MetaCmd {
        name: "/sleep",
        args_hint: "<secs> [jitter%]",
        help: "set beacon interval",
        icon: "⏱",
    },
    MetaCmd {
        name: "/ping",
        args_hint: "",
        help: "liveness probe",
        icon: "∻",
    },
    MetaCmd {
        name: "/screenshot",
        args_hint: "[monitor]",
        help: "capture screen",
        icon: "▣",
    },
    MetaCmd {
        name: "/portscan",
        args_hint: "<host> <ports>",
        help: "scan ports",
        icon: "⊚",
    },
    MetaCmd {
        name: "/net",
        args_hint: "<ifconfig|arp|routes|conn>",
        help: "network info",
        icon: "⌚",
    },
    MetaCmd {
        name: "/drive",
        args_hint: "",
        help: "disk info",
        icon: "◈",
    },
    MetaCmd {
        name: "/clipboard",
        args_hint: "",
        help: "read clipboard",
        icon: "⎘",
    },
    MetaCmd {
        name: "/env",
        args_hint: "[name]",
        help: "environment vars",
        icon: "⌘",
    },
    MetaCmd {
        name: "/keylog",
        args_hint: "<start|stop|dump|stream [secs]|unstream>",
        help: "keystroke logger (stream = continuous dump)",
        icon: "⌨",
    },
    MetaCmd {
        name: "/screenwatch",
        args_hint: "<secs>",
        help: "periodic screenshots",
        icon: "▣",
    },
    MetaCmd {
        name: "/hashdump",
        args_hint: "[sam|system|shadow]",
        help: "credential hashes (sam=0 system=1 shadow=3)",
        icon: "⚿",
    },
    MetaCmd {
        name: "/getuid",
        args_hint: "",
        help: "current thread identity",
        icon: "①",
    },
    MetaCmd {
        name: "/inject",
        args_hint: "<method> <pid|spawn_to> <file>",
        help: "inject shellcode (method 0=pool/stomp 1=threadless 2=stomp)",
        icon: "⚕",
    },
    MetaCmd {
        name: "/steal",
        args_hint: "<pid>",
        help: "steal a process token",
        icon: "↻",
    },
    MetaCmd {
        name: "/make_token",
        args_hint: "<domain\\user> <password> [1|2|3]",
        help: "make a logon token",
        icon: "◆",
    },
    MetaCmd {
        name: "/rev2self",
        args_hint: "",
        help: "drop impersonation (keep token)",
        icon: "↻",
    },
    MetaCmd {
        name: "/pivot",
        args_hint: "<host> <port>",
        help: "outbound connect (P2P)",
        icon: "⇄",
    },
    MetaCmd {
        name: "/socks",
        args_hint: "start [addr] | stop | <chan> <op> <addr> <port>",
        help: "SOCKS5 relay (start/stop) or manual channel control",
        icon: "◎",
    },
    MetaCmd {
        name: "/chan close",
        args_hint: "<id>",
        help: "close relay channel",
        icon: "⊘",
    },
    MetaCmd {
        name: "/kill",
        args_hint: "",
        help: "task the beacon to exit",
        icon: "☠",
    },
    MetaCmd {
        name: "/clear",
        args_hint: "",
        help: "clear the event stream",
        icon: "⊖",
    },
    MetaCmd {
        name: "/theme",
        args_hint: "[mocha|frappe|macchiato|highcontrast|nocolor]",
        help: "switch color theme (or show current)",
        icon: "◐",
    },
    MetaCmd {
        name: "/config",
        args_hint: "[stream_cap <N>]",
        help: "show / set runtime config (stream_cap)",
        icon: "⚙",
    },
    MetaCmd {
        name: "/driver-status",
        args_hint: "",
        help: "kernel daemon status",
        icon: "⚙",
    },
    MetaCmd {
        name: "/blind-etw",
        args_hint: "",
        help: "blind ETW-TI kernel provider",
        icon: "⊘",
    },
    MetaCmd {
        name: "/hide",
        args_hint: "<pid>",
        help: "DKOM process hide",
        icon: "◈",
    },
    MetaCmd {
        name: "/dump-lsass",
        args_hint: "<pid>",
        help: "kernel LSASS dump",
        icon: "⚿",
    },
    MetaCmd {
        name: "/neutralize",
        args_hint: "<pid>",
        help: "neutralize EDR callbacks",
        icon: "☠",
    },
    MetaCmd {
        name: "/detach-mf",
        args_hint: "",
        help: "detach EDR minifilter",
        icon: "✕",
    },
    MetaCmd {
        name: "/trex",
        args_hint: "",
        help: "T-REX target recon (noise-graded EDR detection)",
        icon: "🦖",
    },
    MetaCmd {
        name: "/channel",
        args_hint: "[0-8|https|doh|dns|smb|tcp|slack|llm|mcp|discord]",
        help: "switch C2 transport channel (no arg = list all)",
        icon: "📡",
    },
    // ── Implant generation ───────────────────────────────────────────────
    MetaCmd {
        name: "/generate",
        args_hint:
            "<callback> [port] [--sleep N] [--jitter N] [--tls/--no-tls] [--format dll|shellcode]",
        help: "generate a per-implant binary with unique keypair + auth token",
        icon: "⚙",
    },
    MetaCmd {
        name: "/implants",
        args_hint: "",
        help: "list all generated implants",
        icon: "☰",
    },
    MetaCmd {
        name: "/revoke",
        args_hint: "<implant_pub>",
        help: "revoke a generated implant",
        icon: "✕",
    },
    MetaCmd {
        name: "/help",
        args_hint: "",
        help: "show this list",
        icon: "❓",
    },
];

// ---- parsed input model ----------------------------------------------------

/// Result of classifying a typed line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Input {
    /// Empty line — nothing to do.
    Empty,
    /// Doesn't start with `/` → a shell command for the current beacon.
    Shell(String),
    /// Starts with `/`. `name` includes the leading slash, lowercased.
    Meta { name: String, args: String },
}

/// Classify a raw input line. Pure function — tested directly.
pub(crate) fn classify(raw: &str) -> Input {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Input::Empty;
    }
    if trimmed.starts_with('/') {
        let (name, rest) = match trimmed.split_once(char::is_whitespace) {
            Some((n, r)) => (n.to_string(), r.trim().to_string()),
            None => (trimmed.to_string(), String::new()),
        };
        Input::Meta {
            name: name.to_ascii_lowercase(),
            args: rest,
        }
    } else {
        Input::Shell(trimmed.to_string())
    }
}

/// Filter the `/` catalogue by the current prefix (e.g. `/l` → `/ls`).
/// `prefix` includes the leading slash. Pure function — tested directly.
pub(crate) fn filter_meta(prefix: &str) -> Vec<&'static MetaCmd> {
    let p = prefix.trim().to_ascii_lowercase();
    META_COMMANDS
        .iter()
        .filter(|m| m.name.starts_with(&p))
        .collect()
}

// ---- popup selection movement ---------------------------------------------

/// Direction of arrow-key movement in the popup.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PopupMove {
    Up,
    Down,
}

/// Compute the next popup selection index given the filtered list length, the
/// current index, and a movement direction. Wraps around at both ends
/// (opencode-style: Down at the bottom → top, Up at the top → bottom).
///
/// Pure function — tested directly. Returns the new index (None if the list is
/// empty).
pub(crate) fn move_popup_selection(
    len: usize,
    current: Option<usize>,
    dir: PopupMove,
) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let cur = current.unwrap_or(0).min(len - 1);
    Some(match dir {
        PopupMove::Up => cur.checked_sub(1).unwrap_or(len - 1),
        PopupMove::Down => {
            if cur + 1 >= len {
                0
            } else {
                cur + 1
            }
        }
    })
}

/// What `Enter` should do when the popup is open. If a single command uniquely
/// matches the typed prefix, or a popup row is selected, return that command's
/// name (so the caller can run it). Otherwise `None` (caller falls back to
/// treating the raw input as-as).
///
/// `input` is the current text in the box (e.g. `/ls`, `/use abc`).
/// `selected` is the popup's selected index (if any).
pub(crate) fn popup_submit_target(input: &str, selected: Option<usize>) -> Option<&'static str> {
    let filtered = filter_meta(input);
    // An explicit selection wins (↑↓ then Enter).
    if let Some(i) = selected {
        if let Some(m) = filtered.get(i) {
            return Some(m.name);
        }
    }
    // Unique prefix match → auto-resolve (e.g. `/ls` matches only /ls).
    if filtered.len() == 1 {
        return Some(filtered[0].name);
    }
    None
}

// ---- scroll ----------------------------------------------------------------

/// Direction of a scroll gesture (mouse wheel or touchpad). Maps to how the
/// view should move: `Up` = view earlier content (offset increases), `Down` =
/// view later content (offset decreases toward 0).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScrollDir {
    Up,
    Down,
}

/// Apply a scroll to a bottom-relative offset (`0` = pinned to the latest
/// content). `amount` is the number of lines to move.
///
/// Pure function — tested directly.
pub(crate) fn apply_scroll(offset: usize, dir: ScrollDir, amount: usize) -> usize {
    match dir {
        // viewing older content → offset grows, unbounded (saturating)
        ScrollDir::Up => offset.saturating_add(amount),
        // viewing newer content → offset shrinks toward 0
        ScrollDir::Down => offset.saturating_sub(amount),
    }
}

// ---- /sleep arg parsing ----------------------------------------------------

/// Parsed `/sleep` arguments. Pure function (unit-tested).
#[derive(Debug)]
pub(crate) enum SleepSpec {
    Seconds(u32),
    SecondsJitter(u32, u8),
    /// Bad input; carries the usage message to log.
    Usage(String),
}

/// Parse `/sleep <secs>` or `/sleep <secs> <jitter%>`. The jitter token may
/// have a trailing `%`. `jitter_pct` is clamped to 0..=100.
pub(crate) fn parse_sleep_args(args: &str) -> SleepSpec {
    let mut it = args.split_whitespace();
    let secs = match it.next().and_then(|s| s.parse::<u32>().ok()) {
        Some(s) => s,
        None => {
            return SleepSpec::Usage("usage: /sleep <secs> [jitter%]".into());
        }
    };
    match it.next() {
        None => SleepSpec::Seconds(secs),
        Some(j) => {
            let cleaned = j.trim_end_matches('%');
            match cleaned.parse::<u32>().ok() {
                Some(v) => SleepSpec::SecondsJitter(secs, v.min(100) as u8),
                None => SleepSpec::Usage(format!(
                    "! bad jitter '{j}' — usage: /sleep <secs> [jitter%]"
                )),
            }
        }
    }
}

// ---- secret masking --------------------------------------------------------

/// Mask a secret for display: short secrets → all dots; longer ones show the
/// first 2 and last 2 chars with `••••` between.
pub(crate) fn mask(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 4 {
        return "••••".to_string();
    }
    format!(
        "{}••••{}",
        chars[..2].iter().collect::<String>(),
        chars[chars.len() - 2..].iter().collect::<String>()
    )
}

// ---- destructive-command confirmation --------------------------------------

/// Destructive commands that must prompt for y/N before dispatching.
///
/// Each carries a one-line human-readable description builder. The TUI's
/// `submit` calls [`destructive_confirm`] *before* dispatch; if it returns
/// `Some`, the command is held in a [`super::ConfirmAction`] and re-dispatched
/// verbatim only after the operator presses `y`.
///
/// Pure data — the description strings live here so they're easy to audit in
/// one place and unit-testable.
const DESTRUCTIVE_COMMANDS: &[(&str, &str)] = &[
    (
        "/kill",
        "Kill beacon session — the implant will exit immediately.",
    ),
    ("/rm", "Delete the file/dir on the target."),
    (
        "/hide",
        "Hide process via kernel DKOM — this modifies kernel structures.",
    ),
    (
        "/neutralize",
        "Neutralize EDR callbacks — this is a kernel-level operation.",
    ),
    (
        "/dump-lsass",
        "Dump LSASS memory — this will create a credential dump.",
    ),
];

/// If `raw` is a destructive command (per [`DESTRUCTIVE_COMMANDS`]), return
/// the description string to show in the confirm overlay. `None` otherwise.
///
/// Only the first token is matched (so `/rmdir` is not `/rm`). The caller is
/// responsible for the actual dispatch and the `confirmed` bypass flag.
///
/// Pure function — tested directly.
pub(crate) fn destructive_confirm(raw: &str) -> Option<&'static str> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('/') {
        return None;
    }
    let first = trimmed.split_whitespace().next()?.to_ascii_lowercase();
    DESTRUCTIVE_COMMANDS
        .iter()
        .find(|(name, _)| *name == first)
        .map(|(_, desc)| *desc)
}

// ---- 增强分类：alias 展开 + ! 强制 shell ------------------------------------

/// 增强版 [`classify`]：支持别名（alias）展开和 `!` 强制 shell。
///
/// 优先级：空输入 → `!` 强制 shell → 别名命中 → 原 classify 逻辑。
/// 纯函数，TDD 覆盖。
pub(crate) fn classify_with(
    raw: &str,
    aliases: &std::collections::HashMap<String, String>,
) -> Input {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Input::Empty;
    }
    // `!` 强制 shell：剥掉前导 `!` 后整行原样作为 shell 命令。
    if let Some(rest) = trimmed.strip_prefix('!') {
        let rest = rest.trim();
        if rest.is_empty() {
            // 只有 `!`，没内容 → 无效输入
            return Input::Empty;
        }
        return Input::Shell(rest.to_string());
    }
    // 别名命中：只看首词，展开后拼接用户后续参数。
    let first = trimmed.split_whitespace().next().unwrap();
    if let Some(expanded) = aliases.get(first) {
        // 拼接 alias 名之后的剩余参数（如 `ll /tmp` → `ls -la /tmp`）。
        let rest = trimmed[first.len()..].trim_start();
        if rest.is_empty() {
            return Input::Shell(expanded.clone());
        }
        return Input::Shell(format!("{expanded} {rest}"));
    }
    classify(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn with_empty_is_empty() {
        assert_eq!(classify_with("", &HashMap::new()), Input::Empty);
    }

    #[test]
    fn with_force_shell_strips_bang() {
        assert_eq!(
            classify_with("!ls", &HashMap::new()),
            Input::Shell("ls".into())
        );
    }

    #[test]
    fn with_force_shell_ignores_alias() {
        let mut a = HashMap::new();
        a.insert("ls".into(), "echo hi".into());
        assert_eq!(classify_with("!ls", &a), Input::Shell("ls".into()));
    }

    #[test]
    fn with_alias_hit_expands() {
        let mut a = HashMap::new();
        a.insert("ll".into(), "ls -la".into());
        assert_eq!(classify_with("ll", &a), Input::Shell("ls -la".into()));
    }

    #[test]
    fn with_alias_appends_extra_args() {
        // alias ll=ls -la，输入 `ll /tmp` → `ls -la /tmp`（不吞参数）
        let mut a = HashMap::new();
        a.insert("ll".into(), "ls -la".into());
        assert_eq!(
            classify_with("ll /tmp", &a),
            Input::Shell("ls -la /tmp".into())
        );
    }

    #[test]
    fn with_alias_miss_falls_to_meta() {
        assert_eq!(
            classify_with("/sessions", &HashMap::new()),
            Input::Meta {
                name: "/sessions".into(),
                args: String::new()
            }
        );
    }

    #[test]
    fn with_bang_only_is_empty() {
        assert_eq!(classify_with("!", &HashMap::new()), Input::Empty);
    }

    #[test]
    fn destructive_kill_flags() {
        assert!(destructive_confirm("/kill").is_some());
        assert!(destructive_confirm("/kill  ").is_some());
    }

    #[test]
    fn destructive_rm_with_arg() {
        // arg shouldn't break detection — first token is what matters
        assert!(destructive_confirm("/rm C:\\windows\\temp\\x").is_some());
    }

    #[test]
    fn destructive_neutralize_dump_hide() {
        assert!(destructive_confirm("/neutralize 1337").is_some());
        assert!(destructive_confirm("/dump-lsass 500").is_some());
        assert!(destructive_confirm("/hide 4").is_some());
    }

    #[test]
    fn destructive_prefix_only_not_matched() {
        // /rmdir must NOT be treated as /rm (first-token exact match)
        assert!(destructive_confirm("/rmdir").is_none());
        assert!(destructive_confirm("/killer").is_none());
    }

    #[test]
    fn destructive_safe_commands_pass_through() {
        assert!(destructive_confirm("/sessions").is_none());
        assert!(destructive_confirm("/ls").is_none());
        assert!(destructive_confirm("ls -la").is_none()); // shell, not slash
        assert!(destructive_confirm("").is_none());
    }
}
