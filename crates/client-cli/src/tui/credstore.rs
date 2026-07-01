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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
                CredStore {
                    entries: file.entries,
                }
            }
            Err(_) => CredStore {
                entries: Vec::new(),
            },
        }
    }

    /// 写入默认路径 `~/.nyx/creds.json`。临时文件 + 原子 rename，设 0600 权限。
    pub fn save(&self) -> std::io::Result<()> {
        self.save_to(&Self::path())
    }

    /// 写入指定路径。临时文件 + 原子 rename，避免写一半崩溃损坏凭据库；
    /// Unix 下文件 0600、目录 0700（凭据库含明文 secret，不能 world-readable）。
    pub fn save_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            // Directory 0700 (Unix only). This is defense-in-depth — the file's
            // 0600 below is the primary control on the secrets themselves, so a
            // permissive dir only exposes the directory's existence, not its
            // contents. Intentionally best-effort and non-fatal: a rare dir-chmod
            // failure must not block saving credentials, and (unlike the file)
            // there's no plaintext leak from leaving the dir at its created mode.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(mut perms) = fs::metadata(parent).map(|m| m.permissions()) {
                    perms.set_mode(0o700);
                    let _ = fs::set_permissions(parent, perms);
                }
            }
        }
        let file = CredFile {
            entries: self.entries.clone(),
        };
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // 写临时文件再 rename（原子），避免写一半崩溃损坏凭据库。
        let tmp = path.with_extension("json.tmp");
        // 先创建并写入临时文件（修复前的 bug：序列化了 json 却从未写盘，导致
        // tmp 不存在、rename 必然失败、凭据库永远存不下来）。
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        // File permissions are only managed strictly on Unix platforms.
        // On Windows, the file will be created with default inherited ACLs.
        //
        // SECURITY: `File::create` made this temp 0644 (world-readable on a
        // typical umask) and it holds plaintext secrets, so 0600 is mandatory.
        // Fail CLOSED on chmod failure: remove the plaintext temp and return an
        // error so the caller knows the creds were NOT saved securely — never
        // leave a world-readable creds file behind. (Previously the chmod result
        // was `let _ =`-ignored, which could silently leave creds world-readable
        // — same silent-failure class as the old save()-never-wrote bug.)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match fs::metadata(&tmp).map(|m| {
                let mut p = m.permissions();
                p.set_mode(0o600);
                p
            }) {
                Ok(perms) => {
                    if let Err(e) = fs::set_permissions(&tmp, perms) {
                        let _ = fs::remove_file(&tmp);
                        return Err(std::io::Error::other(format!(
                            "could not chmod cred file {} to 0600 ({e}); refusing to leave \
                             plaintext credentials world-readable",
                            tmp.display()
                        )));
                    }
                }
                Err(e) => {
                    let _ = fs::remove_file(&tmp);
                    return Err(e);
                }
            }
        }
        fs::rename(&tmp, path)
    }

    /// 从一次 dump 入库。去重：(principal, secret, kind) 三元组唯一。
    /// 返回新增数。
    pub fn ingest(&mut self, creds: &[CredEntry], beacon: Option<&str>) -> usize {
        let collected_at = now_secs();
        let beacon_owned = beacon.map(|s| s.to_string());
        let start = self.entries.len();
        for c in creds {
            let dup = self
                .entries
                .iter()
                .any(|e| e.principal == c.principal && e.secret == c.secret && e.kind == c.kind);
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
        let file = CredFile {
            entries: self.entries.clone(),
        };
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
        CredEntry {
            source: source.to_string(),
            principal: principal.to_string(),
            kind,
            secret: secret.to_string(),
        }
    }

    #[test]
    fn ingest_dedups() {
        let mut store = CredStore {
            entries: Vec::new(),
        };
        let creds = vec![
            entry("DEV", "alice", CredKind::Hash, "deadbeef"),
            entry("DEV", "alice", CredKind::Hash, "deadbeef"),
        ];
        assert_eq!(store.ingest(&creds, Some("b1")), 1);
    }

    #[test]
    fn ingest_same_secret_diff_kind_not_deduped() {
        // 同 principal+secret 但 kind 不同 → 不去重（审计 P1 修复）
        let mut store = CredStore {
            entries: Vec::new(),
        };
        let creds = vec![
            entry("", "alice", CredKind::Hash, "xyz"),
            entry("", "alice", CredKind::Password, "xyz"),
        ];
        assert_eq!(store.ingest(&creds, None), 2);
    }

    #[test]
    fn search_kind_hash() {
        let mut store = CredStore {
            entries: Vec::new(),
        };
        store.ingest(
            &[
                entry("", "a", CredKind::Hash, "h"),
                entry("", "b", CredKind::Password, "p"),
            ],
            None,
        );
        assert_eq!(store.search("kind:hash").len(), 1);
    }

    #[test]
    fn search_user_fuzzy() {
        let mut store = CredStore {
            entries: Vec::new(),
        };
        store.ingest(
            &[
                entry("", "Administrator", CredKind::Hash, "a"),
                entry("", "guest", CredKind::Hash, "g"),
            ],
            None,
        );
        assert_eq!(store.search("user:admin").len(), 1);
    }

    #[test]
    fn search_empty_returns_all() {
        let mut store = CredStore {
            entries: Vec::new(),
        };
        store.ingest(
            &[
                entry("", "a", CredKind::Hash, "1"),
                entry("", "b", CredKind::Password, "2"),
            ],
            None,
        );
        assert_eq!(store.search("").len(), 2);
    }

    #[test]
    fn export_csv_header() {
        let mut store = CredStore {
            entries: Vec::new(),
        };
        store.ingest(
            &[entry("DEV", "alice", CredKind::Hash, "deadbeef")],
            Some("b1"),
        );
        let csv = store.export_csv();
        assert_eq!(
            csv.lines().next().unwrap(),
            "source,principal,kind,secret,beacon,collected_at"
        );
    }

    #[test]
    fn export_csv_escapes_commas() {
        let mut store = CredStore {
            entries: Vec::new(),
        };
        store.ingest(&[entry("", "bob", CredKind::Password, "p,w")], None);
        let csv = store.export_csv();
        let body = csv.lines().nth(1).unwrap();
        assert!(body.contains("\"p,w\""));
    }

    #[test]
    fn json_roundtrip_basic() {
        let mut store = CredStore {
            entries: Vec::new(),
        };
        store.ingest(
            &[entry("DEV", "alice", CredKind::Hash, "deadbeef")],
            Some("b1"),
        );
        let json = store.export_json();
        let file: CredFile = serde_json::from_str(&json).unwrap();
        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.entries[0].principal, "alice");
        assert_eq!(file.entries[0].beacon.as_deref(), Some("b1"));
    }

    #[test]
    fn json_roundtrip_special_chars() {
        // 审计 P1：含引号/反斜杠/换行/中文 的 secret 必须正确 roundtrip
        let mut store = CredStore {
            entries: Vec::new(),
        };
        store.ingest(
            &[entry(
                "",
                "a\"principal",
                CredKind::Password,
                "p\\n\"x\n中文\tend",
            )],
            None,
        );
        let json = store.export_json();
        let file: CredFile = serde_json::from_str(&json).unwrap();
        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.entries[0].secret, "p\\n\"x\n中文\tend");
        assert_eq!(file.entries[0].principal, "a\"principal");
    }

    /// 唯一的临时路径（不依赖 tempfile crate）。调用方负责清理。
    fn tmp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!(
            "nyx_credstore_test_{tag}_{nano}_{pid}.json",
            tag = tag,
            nano = nanos,
            pid = std::process::id()
        ));
        p
    }

    #[test]
    fn save_to_actually_writes_file() {
        // 回归测试：save() 历史上序列化了 json 却从不写入临时文件，导致凭据库
        // 永远落不了盘。save_to(path) 必须真正创建文件并写入 JSON 内容。
        let path = tmp_path("write");
        let mut store = CredStore {
            entries: Vec::new(),
        };
        store.ingest(
            &[entry("DEV", "alice", CredKind::Hash, "deadbeef")],
            Some("b1"),
        );

        store.save_to(&path).expect("save_to should succeed");

        // 文件确实被创建（修复前：tmp 从未写入 → rename 失败 → 文件不存在）
        assert!(path.exists(), "creds file must exist after save_to");
        // 内容是合法 JSON 且能 roundtrip
        let bytes = fs::read(&path).expect("should read back written file");
        let file: CredFile = serde_json::from_slice(&bytes).expect("written content is valid JSON");
        assert_eq!(file.entries.len(), 1);
        assert_eq!(file.entries[0].principal, "alice");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn save_to_overwrites_existing() {
        // 二次保存应原子替换，不残留旧内容或 .tmp 文件。
        let path = tmp_path("overwrite");
        let mut store = CredStore {
            entries: Vec::new(),
        };
        store.ingest(&[entry("D", "u1", CredKind::Hash, "s1")], None);
        store.save_to(&path).unwrap();
        store.ingest(&[entry("D", "u2", CredKind::Hash, "s2")], None);
        store.save_to(&path).unwrap();

        let bytes = fs::read(&path).unwrap();
        let file: CredFile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(file.entries.len(), 2);
        // 不应残留 .tmp 临时文件
        let tmp = path.with_extension("json.tmp");
        assert!(!tmp.exists(), "no leftover .tmp file after atomic rename");
        let _ = fs::remove_file(&path);
    }
}
