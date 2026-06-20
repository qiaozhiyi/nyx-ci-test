//! Parsers that turn raw `shell` command output into structured domain rows.
//!
//! The server protocol has no dedicated ls/ps/creds commands, so we run plain
//! shell commands (`ls -la`, `ps aux`, `cmd /c dir`, `tasklist /fo csv`) and
//! parse the text here. Each parser is a free function taking `&str` output and
//! returning `Vec<...>`; they never panic on malformed input (best-effort skip).

use crate::types::{CredEntry, CredKind, FileEntry, ProcEntry};

// ---- POSIX: `ls -l` (and `ls -la`) -----------------------------------------
// Sample (macOS):
//   total 48
//   drwxr-xr-x@ 4 user  staff    128 May 21 16:57 .
//   -rw-r--r--  1 user  staff   1234 May 21 16:57 notes.txt
//   lrwxr-xr-x  1 root  wheel     11 May 21 16:57 link -> target
//
// Fields: perms links owner group size month day time/name. The last whitespace
// group is the name (may contain ` -> target` for symlinks; we drop the target).
// Directory ⟺ perms start with 'd'. Size is field index 4. The date is the
// 3 fields before the name; we join them into `modified`.

pub fn parse_ls_posix(out: &str) -> Vec<FileEntry> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with("total ") {
            continue;
        }
        // perms must start with a file-type char we recognize
        let first = match line.chars().next() {
            Some(c) if matches!(c, 'd' | '-' | 'l' | 'c' | 'b' | 'p' | 's') => c,
            _ => continue,
        };
        let mut it = line.split_whitespace();
        let perms = it.next().unwrap_or("");
        // links
        let _links = it.next();
        let _owner = it.next();
        let _group = it.next();
        let size: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let month = it.next().unwrap_or("");
        let day = it.next().unwrap_or("");
        // time/year field
        let when = it.next().unwrap_or("");
        // remainder is the name (possibly `name -> target`)
        let rest: String = it.collect::<Vec<_>>().join(" ");
        let name = match rest.split_once(" -> ") {
            Some((n, _)) => n.to_string(),
            None => rest,
        };
        if name.is_empty() {
            continue;
        }
        let is_dir = perms.starts_with('d') || first == 'd';
        rows.push(FileEntry {
            name,
            size,
            is_dir,
            modified: format!("{month} {day} {when}"),
        });
    }
    rows
}

// ---- POSIX: `ps aux` -------------------------------------------------------
// Header: USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND
// Fields we keep: USER(0) PID(1) ... COMMAND(last, may contain spaces).
// ppid is not present in `ps aux` → 0. name = COMMAND's basename.

pub fn parse_ps_posix(out: &str) -> Vec<ProcEntry> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let mut it = line.split_whitespace();
        let user = match it.next() {
            Some(u) => u.to_string(),
            None => continue,
        };
        // skip header
        if user == "USER" {
            continue;
        }
        let pid: u32 = match it.next().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        // %cpu %mem vsz rss tt stat started time  (7 fields) then COMMAND
        for _ in 0..7 {
            it.next();
        }
        let cmd: String = it.collect::<Vec<_>>().join(" ");
        if cmd.is_empty() {
            continue;
        }
        // name = the basename of the executable (after the last '/'), then drop
        // any args that followed it on the same command line.
        let tail = cmd.rsplit('/').next().unwrap_or(&cmd);
        let name = tail.split_whitespace().next().unwrap_or(tail).to_string();
        rows.push(ProcEntry {
            pid,
            ppid: 0,
            name,
            user,
        });
    }
    rows
}

// ---- Windows: `tasklist /fo csv /nh` --------------------------------------
// Sample:
//   "System Idle Process","0","Services","0","8,192 K"
//   "chrome.exe","17352","Console","1","668,496 K"
// Fields: ImageName,PID,SessionName,Session#,MemUsage. ppid unavailable → 0.

pub fn parse_tasklist_win(out: &str) -> Vec<ProcEntry> {
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
        rows.push(ProcEntry {
            pid,
            ppid: 0,
            name,
            user,
        });
    }
    rows
}

// ---- Windows: `cmd /c dir` -------------------------------------------------
// Sample:
//   05/21/2026  04:57 PM    <DIR>          .
//   05/21/2026  04:57 PM             1,234 notes.txt
// Date time then either <DIR> or size, then name.

pub fn parse_dir_win(out: &str) -> Vec<FileEntry> {
    let mut rows = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // need at least date + time to look like an entry
        let mut it = line.split_whitespace();
        let date = match it.next() {
            Some(d) if d.contains('/') || d.contains('-') => d.to_string(),
            _ => continue,
        };
        let time = it.next().unwrap_or("");
        let ampm = it.next().unwrap_or("");
        let token = it.next().unwrap_or("");
        let (is_dir, size) = if token.eq_ignore_ascii_case("<DIR>") {
            (true, 0u64)
        } else {
            let cleaned = token.replace(',', "");
            match cleaned.parse::<u64>() {
                Ok(s) => (false, s),
                Err(_) => continue,
            }
        };
        let name: String = it.collect::<Vec<_>>().join(" ");
        if name.is_empty() {
            continue;
        }
        rows.push(FileEntry {
            name,
            size,
            is_dir,
            modified: format!("{date} {time} {ampm}"),
        });
    }
    rows
}

// ---- Credentials: generic key:value dump -----------------------------------
// Accepts lines like `source\principal : HASH : <secret>` ( Mimikatz-ish) or
// `principal:secret` / `principal hash <secret>`. We detect kind by the secret
// shape: 32 hex → hash, otherwise password.
//
// Supported minimal format (one record per line):
//   <source>\<principal> : <kind> : <secret>
// where <kind> is one of hash|password|ticket|key (case-insensitive). Lines that
// don't match are skipped.

pub fn parse_creds(out: &str) -> Vec<CredEntry> {
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
            "hash" => CredKind::Hash,
            "password" => CredKind::Password,
            "ticket" => CredKind::Ticket,
            "key" => CredKind::Key,
            _ => continue,
        };
        let (source, principal) = match who.split_once('\\') {
            Some((s, p)) => (s.to_string(), p.to_string()),
            None => (String::new(), who.to_string()),
        };
        rows.push(CredEntry {
            source,
            principal,
            kind,
            secret: secret.to_string(),
        });
    }
    rows
}

/// Auto-detect the listing format (Windows `dir` vs POSIX `ls -l`) by sniffing
/// the first content line, and parse accordingly. Returns whichever yields rows.
pub fn parse_any_files(out: &str) -> Vec<FileEntry> {
    // Windows `dir` lines start with a date (MM/DD/YYYY or DD-MM-YYYY).
    let looks_win = out.lines().find(|l| !l.trim().is_empty()).is_some_and(|l| {
        let head = l.trim_start();
        // a date-ish token: digits sep digits sep digits
        let tok = head.split_whitespace().next().unwrap_or("");
        tok.chars().filter(|c| c.is_ascii_digit()).count() >= 4
            && (tok.contains('/') || tok.contains('-'))
            && !tok.starts_with(['d', '-', 'l', 'c', 'b', 'p', 's'])
    });
    let win = if looks_win { parse_dir_win(out) } else { Vec::new() };
    if !win.is_empty() {
        return win;
    }
    parse_ls_posix(out)
}

/// Auto-detect the process format (Windows `tasklist` CSV vs POSIX `ps aux`).
pub fn parse_any_procs(out: &str) -> Vec<ProcEntry> {
    // Windows tasklist /fo csv quotes every field.
    let looks_win = out
        .lines()
        .find(|l| !l.trim().is_empty())
        .is_some_and(|l| l.trim_start().starts_with('"'));
    let win = if looks_win { parse_tasklist_win(out) } else { Vec::new() };
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
        let sample = "\n\nhello world\nnot a listing\n";
        assert!(parse_ls_posix(sample).is_empty());
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

    // ---- dir (Windows) ----

    #[test]
    fn dir_win_parses_dir_and_file() {
        let sample = "05/21/2026  04:57 PM    <DIR>          sub\n\
                      05/21/2026  04:57 PM             1,234 notes.txt\n";
        let rows = parse_dir_win(sample);
        assert_eq!(rows.len(), 2);
        assert!(rows[0].is_dir);
        assert_eq!(rows[0].name, "sub");
        assert!(!rows[1].is_dir);
        assert_eq!(rows[1].name, "notes.txt");
        assert_eq!(rows[1].size, 1234);
    }

    #[test]
    fn dir_win_skips_volume_and_summary_lines() {
        let sample = " Volume in drive C\n Directory of C:\\Users\n";
        assert!(parse_dir_win(sample).is_empty());
    }

    // ---- creds ----

    #[test]
    fn creds_parses_mimikatz_style() {
        let sample = "DEV\\alice : hash : 8846f7eaee8fb117ad06bdd830b7586c\n";
        let rows = parse_creds(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "DEV");
        assert_eq!(rows[0].principal, "alice");
        assert_eq!(rows[0].kind, CredKind::Hash);
        assert_eq!(rows[0].secret, "8846f7eaee8fb117ad06bdd830b7586c");
    }

    #[test]
    fn creds_handles_no_domain() {
        let sample = "bob : password : hunter2\n";
        let rows = parse_creds(sample);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source, "");
        assert_eq!(rows[0].principal, "bob");
        assert_eq!(rows[0].kind, CredKind::Password);
    }

    #[test]
    fn creds_skips_malformed() {
        let sample = "garbage line\nx : y\n\n";
        assert!(parse_creds(sample).is_empty());
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
