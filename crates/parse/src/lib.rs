//! Shell-output parsers that turn raw command output (`ls -la`, `ps aux`,
//! `cmd /c dir`, `tasklist /fo csv`) into neutral domain rows.
//!
//! This is the **single source of truth** for the parsing logic shared by the
//! Nyx `client-ui` (Makepad) and `client-cli` (TUI) operator clients. It used
//! to live as two verbatim-duplicated copies — one per crate — which meant a
//! parser bug fixed in one silently stayed broken in the other (that is exactly
//! how the `parse_ps_posix` off-by-one survived: fixed in client-ui, missed in
//! client-cli). Centralising it here makes that class of drift impossible.
//!
//! Each parser is a free function `&str -> Vec<Row>`; they never panic on
//! malformed input (best-effort skip). The row types are intentionally neutral
//! (`FileRow` / `ProcRow` / `CredRow`) and carry no UI concerns (e.g. no
//! `arch`) — each client maps them to its own widget/CLI types via `From`.

#![forbid(unsafe_code)]

// ---- neutral row types ---------------------------------------------------

/// One entry from a directory listing (`ls -l` / `dir`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub modified: String,
}

/// One process row (`ps aux` / `tasklist`). `ppid` is 0 when the source format
/// doesn't expose it. There is deliberately no `arch` field here — that is a
/// UI-display concern; clients fill it from their own context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcRow {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub user: String,
}

/// One harvested credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredRow {
    pub source: String,
    pub principal: String,
    pub kind: Kind,
    pub secret: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Hash,
    Password,
    Ticket,
    Key,
}

// ---- POSIX: `ls -l` (and `ls -la`) ---------------------------------------

pub fn parse_ls_posix(out: &str) -> Vec<FileRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with("total ") {
            continue;
        }
        let first = match line.chars().next() {
            Some(c) if matches!(c, 'd' | '-' | 'l' | 'c' | 'b' | 'p' | 's') => c,
            _ => continue,
        };
        let mut it = line.split_whitespace();
        let perms = it.next().unwrap_or("");
        let _links = it.next();
        let _owner = it.next();
        let _group = it.next();
        let size: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let month = it.next().unwrap_or("");
        let day = it.next().unwrap_or("");
        let when = it.next().unwrap_or("");
        let rest: String = it.collect::<Vec<_>>().join(" ");
        let name = match rest.split_once(" -> ") {
            Some((n, _)) => n.to_string(),
            None => rest,
        };
        if name.is_empty() {
            continue;
        }
        rows.push(FileRow {
            name,
            size,
            is_dir: perms.starts_with('d') || first == 'd',
            modified: format!("{month} {day} {when}"),
        });
    }
    rows
}

// ---- POSIX: `ps aux` -----------------------------------------------------
// Columns: USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND (11 total).
// Between PID and COMMAND there are 8 fields — skip all 8, not 7, or the TIME
// field leaks into the command string (see ps_posix_pathless_command_not_eaten
// regression test).

pub fn parse_ps_posix(out: &str) -> Vec<ProcRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let mut it = line.split_whitespace();
        let user = match it.next() {
            Some(u) => u.to_string(),
            None => continue,
        };
        if user == "USER" {
            continue;
        }
        let pid: u32 = match it.next().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        // %cpu %mem vsz rss tt stat started time  (8 fields) then COMMAND
        for _ in 0..8 {
            it.next();
        }
        let cmd: String = it.collect::<Vec<_>>().join(" ");
        if cmd.is_empty() {
            continue;
        }
        let tail = cmd.rsplit('/').next().unwrap_or(&cmd);
        let name = tail.split_whitespace().next().unwrap_or(tail).to_string();
        rows.push(ProcRow {
            pid,
            ppid: 0,
            name,
            user,
        });
    }
    rows
}

// ---- Windows: `tasklist /fo csv /nh` -------------------------------------

pub fn parse_tasklist_win(out: &str) -> Vec<ProcRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() < 2 {
            continue;
        }
        let name = fields[0].clone();
        let pid: u32 = match fields[1].parse().ok() {
            Some(p) => p,
            None => continue,
        };
        let user = fields.get(2).cloned().unwrap_or_default();
        rows.push(ProcRow {
            pid,
            ppid: 0,
            name,
            user,
        });
    }
    rows
}

// ---- Windows: `cmd /c dir` -----------------------------------------------
// A line is:  date  time  [AM|PM]  (<DIR>|size)  name
// The AM/PM token is only present in 12-hour locales; in a 24-hour locale the
// token after `time` is directly the <DIR>/size. Sniff it so both locales parse.

pub fn parse_dir_win(out: &str) -> Vec<FileRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let date = match it.next() {
            // Accept all three Windows short-date separators: `/` (en-US),
            // `-` (ISO/some locales), and `.` (de-DE dd.MM.yyyy). Without `.`
            // the entire listing is silently dropped in dot-separator locales.
            Some(d) if d.contains('/') || d.contains('-') || d.contains('.') => d.to_string(),
            _ => continue,
        };
        let time = it.next().unwrap_or("").to_string();
        // tok1 is EITHER the <DIR>/size (24-hour locale) OR an AM/PM marker
        // (12-hour locale, followed by the real <DIR>/size token).
        let tok1 = it.next();
        let (ampm, size_tok) = match tok1 {
            Some(t) if t.eq_ignore_ascii_case("<DIR>") || is_size_token(t) => (None, tok1),
            Some(_) => (tok1, it.next()),
            None => (None, None),
        };
        let (is_dir, size) = match size_tok {
            Some(t) if t.eq_ignore_ascii_case("<DIR>") => (true, 0u64),
            Some(t) if is_size_token(t) => (false, parse_size(t)),
            _ => continue,
        };
        let name: String = it.collect::<Vec<_>>().join(" ");
        if name.is_empty() {
            continue;
        }
        let modified = match ampm {
            Some(a) => format!("{date} {time} {a}"),
            None => format!("{date} {time}"),
        };
        rows.push(FileRow {
            name,
            size,
            is_dir,
            modified,
        });
    }
    rows
}

/// A token is a file size if, after stripping thousands separators, it is a
/// non-empty run of ASCII digits (`1,234`, `1234`). Anything else (AM/PM,
/// `<DIR>`, a name) is not.
fn is_size_token(t: &str) -> bool {
    let c = t.replace(',', "");
    !c.is_empty() && c.chars().all(|ch| ch.is_ascii_digit())
}

fn parse_size(t: &str) -> u64 {
    t.replace(',', "").parse().unwrap_or(0)
}

// ---- Credentials: `source\principal : kind : secret` ---------------------

pub fn parse_creds(out: &str) -> Vec<CredRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(" : ").collect();
        if parts.len() != 3 {
            continue;
        }
        let (who, kind_str, secret) = (parts[0], parts[1], parts[2]);
        let kind = match kind_str.to_ascii_lowercase().as_str() {
            "hash" => Kind::Hash,
            "password" => Kind::Password,
            "ticket" => Kind::Ticket,
            "key" => Kind::Key,
            _ => continue,
        };
        let (source, principal) = match who.split_once('\\') {
            Some((s, p)) => (s.to_string(), p.to_string()),
            None => (String::new(), who.to_string()),
        };
        rows.push(CredRow {
            source,
            principal,
            kind,
            secret: secret.to_string(),
        });
    }
    rows
}

// ---- auto-detect wrappers ------------------------------------------------

pub fn parse_any_files(out: &str) -> Vec<FileRow> {
    let looks_win = out.lines().find(|l| !l.trim().is_empty()).is_some_and(|l| {
        let head = l.trim_start();
        let tok = head.split_whitespace().next().unwrap_or("");
        tok.chars().filter(|c| c.is_ascii_digit()).count() >= 4
            && (tok.contains('/') || tok.contains('-') || tok.contains('.'))
            && !tok.starts_with(['d', '-', 'l', 'c', 'b', 'p', 's'])
    });
    let win = if looks_win {
        parse_dir_win(out)
    } else {
        Vec::new()
    };
    if !win.is_empty() {
        return win;
    }
    parse_ls_posix(out)
}

pub fn parse_any_procs(out: &str) -> Vec<ProcRow> {
    let looks_win = out
        .lines()
        .find(|l| !l.trim().is_empty())
        .is_some_and(|l| l.trim_start().starts_with('"'));
    let win = if looks_win {
        parse_tasklist_win(out)
    } else {
        Vec::new()
    };
    if !win.is_empty() {
        return win;
    }
    parse_ps_posix(out)
}

/// Minimal CSV field splitter: handles double-quoted fields with no embedded
/// quotes (sufficient for tasklist's simple output).
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    fields.push(cur);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ls -l (POSIX) ----

    #[test]
    fn ls_posix_parses_file_and_dir_and_skips_total() {
        let sample = "total 48\n\
                      drwxr-xr-x@ 4 user  staff    128 May 21 16:57 .\n\
                      -rw-r--r--  1 user  staff   1234 May 21 16:57 notes.txt\n";
        let rows = parse_ls_posix(sample);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].is_dir);
        assert_eq!(rows[0].name, ".");
        assert!(!rows[1].is_dir);
        assert_eq!(rows[1].name, "notes.txt");
        assert_eq!(rows[1].size, 1234);
    }

    #[test]
    fn ls_posix_strips_symlink_target() {
        let sample = "lrwxr-xr-x  1 root  wheel     11 May 21 16:57 link -> target\n";
        let rows = parse_ls_posix(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "link");
        assert_eq!(rows[0].size, 11);
        assert!(!rows[0].is_dir);
    }

    #[test]
    fn ls_posix_ignores_blank_and_garbage() {
        assert!(parse_ls_posix("\n\nhello world\nnot a listing\n").is_empty());
    }

    // ---- ps aux (POSIX) ----

    #[test]
    fn ps_posix_skips_header_and_parses_command_basename() {
        let sample = "USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND\n\
                      qiaozhiyi        17352  24.5  1.8 1898979152 668496   ??  S     4:07PM   5:14.54 /Applications/ZCode.app/Contents/MacOS/zcode --renderer\n";
        let rows = parse_ps_posix(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 17352);
        assert_eq!(rows[0].user, "qiaozhiyi");
        assert_eq!(rows[0].name, "zcode");
    }

    #[test]
    fn ps_posix_name_is_full_cmd_when_no_slash() {
        let sample = "root   1  0.0  0.0 100 4 ?? Ss 9Jun26 0:00.01 /sbin/launchd\n";
        let rows = parse_ps_posix(sample);
        assert_eq!(rows[0].name, "launchd");
    }

    #[test]
    fn ps_posix_pathless_command_not_eaten_by_time_field() {
        // Regression: a `ps aux` line whose COMMAND has no '/' (bare daemons,
        // some Linux kernel-thread labels) used to have the TIME field prepended
        // to the command, because only 7 of the 8 fields between PID and COMMAND
        // were skipped — so the first-word extraction picked up the TIME token
        // ("0:00.01") instead of the executable name. This fails before the fix.
        let sample =
            "root  1234  0.0  0.0  5000   200 ??  Ss  5:20PM  0:00.01 bare_daemon --flag\n";
        let rows = parse_ps_posix(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 1234);
        assert_eq!(
            rows[0].name, "bare_daemon",
            "name must be the executable, not the TIME field"
        );
    }

    // ---- tasklist (Windows CSV) ----

    #[test]
    fn tasklist_win_parses_csv_rows() {
        let sample = "\"System Idle Process\",\"0\",\"Services\",\"0\",\"8,192 K\"\n\
                      \"chrome.exe\",\"17352\",\"Console\",\"1\",\"668,496 K\"\n";
        let rows = parse_tasklist_win(sample);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "System Idle Process");
        assert_eq!(rows[0].pid, 0);
        assert_eq!(rows[1].name, "chrome.exe");
        assert_eq!(rows[1].pid, 17352);
        assert_eq!(rows[1].user, "Console");
    }

    #[test]
    fn tasklist_win_skips_non_numeric_pid() {
        let sample = "\"bad\",\"NaN\",\"Services\"\n\"ok\",\"42\",\"Console\"\n";
        let rows = parse_tasklist_win(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pid, 42);
    }

    // ---- dir (Windows) — 12-hour AND 24-hour locales ----

    #[test]
    fn dir_win_12h_parses_dir_and_file() {
        let sample = "05/21/2026  04:57 PM    <DIR>          sub\n\
                      05/21/2026  04:57 PM             1,234 notes.txt\n";
        let rows = parse_dir_win(sample);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].is_dir);
        assert_eq!(rows[0].name, "sub");
        assert_eq!(rows[0].modified, "05/21/2026 04:57 PM");
        assert!(!rows[1].is_dir);
        assert_eq!(rows[1].name, "notes.txt");
        assert_eq!(rows[1].size, 1234);
    }

    #[test]
    fn dir_win_24h_parses_dir_and_file_without_ampm() {
        // Regression: a 24-hour locale emits no AM/PM token, so the field after
        // `time` is directly the <DIR>/size. The old parser always read an
        // AM/PM field and then mis-parsed the size token as the name, silently
        // dropping every entry. Both locales must now parse.
        let sample = "21/05/2026  16:57    <DIR>          sub\n\
                      21/05/2026  16:57            1,234 notes.txt\n";
        let rows = parse_dir_win(sample);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].is_dir);
        assert_eq!(rows[0].name, "sub");
        assert_eq!(rows[0].modified, "21/05/2026 16:57");
        assert!(!rows[1].is_dir);
        assert_eq!(rows[1].name, "notes.txt");
        assert_eq!(rows[1].size, 1234);
        assert_eq!(rows[1].modified, "21/05/2026 16:57");
    }

    #[test]
    fn dir_win_dot_separated_dates_parse_de_de_locale() {
        // Regression: de-DE (and any locale) with the dd.MM.yyyy short-date
        // format emits dot-separated dates. The date guard used to accept only
        // `/` and `-`, silently dropping every entry. Dot separators must now
        // parse, and the auto-detect wrapper must still route it to the Windows
        // dir parser (not fall through to POSIX ls).
        let sample = "21.05.2026  16:57    <DIR>          sub\n\
                      21.05.2026  16:57            1,234 notes.txt\n";
        let rows = parse_dir_win(sample);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].is_dir);
        assert_eq!(rows[0].name, "sub");
        assert!(!rows[1].is_dir);
        assert_eq!(rows[1].name, "notes.txt");
        assert_eq!(rows[1].size, 1234);
        assert_eq!(
            parse_any_files(sample).len(),
            2,
            "auto-detect must route dot-dates to dir"
        );
    }

    #[test]
    fn dir_win_skips_volume_and_summary_lines() {
        assert!(parse_dir_win(" Volume in drive C\n Directory of C:\\Users\n").is_empty());
    }

    // ---- creds ----

    #[test]
    fn creds_parses_mimikatz_style() {
        let sample = "DEV\\alice : hash : 8846f7eaee8fb117ad06bdd830b7586c\n";
        let rows = parse_creds(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "DEV");
        assert_eq!(rows[0].principal, "alice");
        assert_eq!(rows[0].kind, Kind::Hash);
        assert_eq!(rows[0].secret, "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn creds_handles_no_domain() {
        let sample = "bob : password : hunter2\n";
        let rows = parse_creds(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "");
        assert_eq!(rows[0].principal, "bob");
        assert_eq!(rows[0].kind, Kind::Password);
    }

    #[test]
    fn creds_skips_malformed() {
        assert!(parse_creds("garbage line\nx : y\n\n").is_empty());
    }

    // ---- auto-detect wrappers ----

    #[test]
    fn any_files_picks_posix_from_ls() {
        let sample = "total 8\n-rw-r--r-- 1 u g 10 May 21 16:57 a.txt\n";
        let rows = parse_any_files(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "a.txt");
    }

    #[test]
    fn any_files_picks_windows_from_dir() {
        let sample = "05/21/2026  04:57 PM             1,234 notes.txt\n";
        let rows = parse_any_files(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "notes.txt");
        assert_eq!(rows[0].size, 1234);
    }

    #[test]
    fn any_procs_picks_posix_from_ps_aux() {
        let sample = "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND\n\
                      root 1 0.0 0.0 100 4 ?? Ss 9Jun26 0:00.01 /sbin/launchd\n";
        let rows = parse_any_procs(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "launchd");
    }

    #[test]
    fn any_procs_picks_windows_from_tasklist() {
        let sample = "\"chrome.exe\",\"17352\",\"Console\",\"1\",\"668,496 K\"\n";
        let rows = parse_any_procs(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "chrome.exe");
    }
}
