//! 本地凭据库持久化（阶段 1.6）。
//!
//! `/creds` 解析出的凭据追加落盘到 `~/.nyx/creds.json`，按 (principal, secret,
//! kind) 去重，提供过滤查询与 JSON/CSV 导出。
//!
//! 序列化用 serde_json（安全、转义正确），写盘用临时文件 + 原子 rename，
//! 且设文件权限 0600（凭据库含明文 secret，不能 world-readable）。

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{CredEntry, CredKind};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// 存储的凭据条目。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredCred {
    pub source: String,
    pub principal: String,
    pub kind: CredKind,
    pub secret: String,
    #[serde(default)]
    pub beacon: Option<String>,
    pub collected_at: u64,
}

/// 凭据库容器（顶层 JSON 对象的 entries 数组）。
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct CredFile {
    #[serde(default)]
    entries: Vec<StoredCred>,
}

/// 凭据库，落盘到 `~/.nyx/creds.json`。
pub struct CredStore {
    pub entries: Vec<StoredCred>,
}

impl CredStore {
    pub fn path() -> PathBuf {
        let mut p = home_dir();
        p.push(".nyx");
        p.push("creds.json");
        p
    }

    pub fn load() -> CredStore {
        match fs::read(Self::path()) {
            Ok(bytes) => {
                let file: CredFile = serde_json::from_slice(&bytes).unwrap_or_default();
                CredStore { entries: file.entries }
            }
            Err(_) => CredStore { entries: Vec::new() },
        }
    }

    /// 写入。临时文件 + 原子 rename，设 0600 权限。
    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            // 目录 0700 (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(mut perms) = fs::metadata(parent).map(|m| m.permissions()) {
                    perms.set_mode(0o700);
                    let _ = fs::set_permissions(parent, perms);
                }
            }
        }
        let file = CredFile { entries: self.entries.clone() };
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // 写临时文件再 rename（原子），避免写一半崩溃损坏凭据库。
        let tmp = path.with_extension("json.tmp");
        // File permissions are only managed strictly on Unix platforms.
        // On Windows, the file will be created with default inherited ACLs.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mut perms) = fs::metadata(&tmp).map(|m| m.permissions()) {
                perms.set_mode(0o600);
                let _ = fs::set_permissions(&tmp, perms);
            }
        }
        fs::rename(&tmp, &path)
    }

    /// 从一次 dump 入库。去重：(principal, secret, kind) 三元组唯一。
    /// 返回新增数。
    pub fn ingest(&mut self, creds: &[CredEntry], beacon: Option<&str>) -> usize {
        let collected_at = now_secs();
        let beacon_owned = beacon.map(|s| s.to_string());
        let start = self.entries.len();
        for c in creds {
            let dup = self.entries.iter().any(|e| {
                e.principal == c.principal && e.secret == c.secret && e.kind == c.kind
            });
            if dup {
                continue;
            }
            self.entries.push(StoredCred {
                source: c.source.clone(),
                principal: c.principal.clone(),
                kind: c.kind,
                secret: c.secret.clone(),
                beacon: beacon_owned.clone(),
                collected_at,
            });
        }
        self.entries.len() - start
    }

    /// 搜索：`user:<sub>`（principal 模糊）、`kind:hash`、空=全部。AND 关系。
    pub fn search<'a>(&'a self, query: &str) -> Vec<&'a StoredCred> {
        let q = query.trim();
        if q.is_empty() {
            return self.entries.iter().collect();
        }
        let mut kind_filter: Option<CredKind> = None;
        let mut user_sub: Option<String> = None;
        for tok in q.split_whitespace() {
            if let Some((k, v)) = tok.split_once(':') {
                match k {
                    "kind" => {
                        kind_filter = match v.to_ascii_lowercase().as_str() {
                            "hash" => Some(CredKind::Hash),
                            "password" => Some(CredKind::Password),
                            "ticket" => Some(CredKind::Ticket),
                            "key" => Some(CredKind::Key),
                            _ => None,
                        };
                    }
                    "user" => user_sub = Some(v.to_ascii_lowercase()),
                    _ => {}
                }
            } else {
                user_sub = Some(tok.to_ascii_lowercase());
            }
        }
        self.entries
            .iter()
            .filter(|e| kind_filter.is_none_or(|k| e.kind == k))
            .filter(|e| {
                user_sub
                    .as_ref()
                    .is_none_or(|s| e.principal.to_ascii_lowercase().contains(s))
            })
            .collect()
    }

    pub fn export_json(&self) -> String {
        let file = CredFile { entries: self.entries.clone() };
        serde_json::to_string_pretty(&file).unwrap_or_else(|_| "{}".into())
    }

    pub fn export_csv(&self) -> String {
        let mut out = String::from("source,principal,kind,secret,beacon,collected_at\n");
        for e in &self.entries {
            let beacon = e.beacon.as_deref().unwrap_or("");
            out.push_str(&format!(
                "{},{},{},{},{},{}\n",
                csv_escape(&e.source),
                csv_escape(&e.principal),
                e.kind.label(),
                csv_escape(&e.secret),
                csv_escape(beacon),
                e.collected_at,
            ));
        }
        out
    }
}

fn csv_escape(s: &str) -> String {
    let needs = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');
    if needs {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn home_dir() -> PathBuf {
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h);
    }
    PathBuf::from(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(source: &str, principal: &str, kind: CredKind, secret: &str) -> CredEntry {
        CredEntry { source: source.to_string(), principal: principal.to_string(), kind, secret: secret.to_string() }
    }

    #[test]
    fn ingest_dedups() {
        let mut store = CredStore { entries: Vec::new() };
        let creds = vec![
            entry("DEV", "alice", CredKind::Hash, "deadbeef"),
            entry("DEV", "alice", CredKind::Hash, "deadbeef"),
        ];
        assert_eq!(store.ingest(&creds, Some("b1")), 1);
    }

    #[test]
    fn ingest_same_secret_diff_kind_not_deduped() {
        // 同 principal+secret 但 kind 不同 → 不去重（审计 P1 修复）
        let mut store = CredStore { entries: Vec::new() };
        let creds = vec![
            entry("", "alice", CredKind::Hash, "xyz"),
            entry("", "alice", CredKind::Password, "xyz"),
        ];
        assert_eq!(store.ingest(&creds, None), 2);
    }

    #[test]
    fn search_kind_hash() {
        let mut store = CredStore { entries: Vec::new() };
        store.ingest(&[entry("", "a", CredKind::Hash, "h"), entry("", "b", CredKind::Password, "p")], None);
        assert_eq!(store.search("kind:hash").len(), 1);
    }

    #[test]
    fn search_user_fuzzy() {
        let mut store = CredStore { entries: Vec::new() };
        store.ingest(&[entry("", "Administrator", CredKind::Hash, "a"), entry("", "guest", CredKind::Hash, "g")], None);
        assert_eq!(store.search("user:admin").len(), 1);
    }

    #[test]
    fn search_empty_returns_all() {
        let mut store = CredStore { entries: Vec::new() };
        store.ingest(&[entry("", "a", CredKind::Hash, "1"), entry("", "b", CredKind::Password, "2")], None);
        assert_eq!(store.search("").len(), 2);
    }

    #[test]
    fn export_csv_header() {
        let mut store = CredStore { entries: Vec::new() };
        store.ingest(&[entry("DEV", "alice", CredKind::Hash, "deadbeef")], Some("b1"));
        let csv = store.export_csv();
        assert_eq!(csv.lines().next().unwrap(), "source,principal,kind,secret,beacon,collected_at");
    }

    #[test]
    fn export_csv_escapes_commas() {
        let mut store = CredStore { entries: Vec::new() };
        store.ingest(&[entry("", "bob", CredKind::Password, "p,w")], None);
        let csv = store.export_csv();
        let body = csv.lines().nth(1).unwrap();
        assert!(body.contains("\"p,w\""));
    }

    #[test]
    fn json_roundtrip_basic() {
        let mut store = CredStore { entries: Vec::new() };
        store.ingest(&[entry("DEV", "alice", CredKind::Hash, "deadbeef")], Some("b1"));
        let json = store.export_json();
        let file: CredFile = serde_json::from_str(&json).unwrap();
        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.entries[0].principal, "alice");
        assert_eq!(file.entries[0].beacon.as_deref(), Some("b1"));
    }

    #[test]
    fn json_roundtrip_special_chars() {
        // 审计 P1：含引号/反斜杠/换行/中文 的 secret 必须正确 roundtrip
        let mut store = CredStore { entries: Vec::new() };
        store.ingest(
            &[entry("", "a\"principal", CredKind::Password, "p\\n\"x\n中文\tend")],
            None,
        );
        let json = store.export_json();
        let file: CredFile = serde_json::from_str(&json).unwrap();
        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.entries[0].secret, "p\\n\"x\n中文\tend");
        assert_eq!(file.entries[0].principal, "a\"principal");
    }
}
