//! Append-only action audit log (Phase 3 v1) — "who tasked WHAT".
//!
//! JSON-lines at `NYX_AUDIT_LOG` (default `~/.nyx/audit.jsonl`): one record per
//! line, grep-/jq-able for after-action reporting. Each record carries a SHA-256
//! hash-chain link (`hash = H(seq || ts || operator || action || target ||
//! detail || prev_hash)`) so a deleted/edited middle page is detectable (a
//! broken link) — tamper-evident against casual edits, NOT against a privileged
//! disk-level adversary (documented honestly).
//!
//! Attribution: `operator` comes from the Phase 3 [`crate::operators`] auth
//! resolution. Server/beacon-originated events record `operator = "system"`.
//!
//! v1 writes are synchronous + flush-per-record (durable against clean
//! shutdown; a hard crash can lose the last unflushed line, which the `seq` gap
//! reveals). Rotation + remote shipping are v2.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub ts: u64,
    pub operator: String,
    pub action: String,
    pub target: String,
    pub detail: serde_json::Value,
    pub prev_hash: String,
    pub hash: String,
}

/// Query filters for `GET /api/audit`.
#[derive(Debug, Default, Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    /// `?dir=asc` for oldest-first; default is newest-first.
    #[serde(default)]
    pub dir: Option<String>,
}

pub struct AuditWriter {
    inner: Mutex<Inner>,
    path: PathBuf,
}

struct Inner {
    file: File,
    seq: u64,
    last_hash: String,
}

impl AuditWriter {
    /// Open (or create) the audit log at `path`. Recovers `seq` + `last_hash`
    /// from existing lines so the hash-chain stays continuous across restart.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Recover chain state from existing content (if any).
        let (mut seq, mut last_hash) = (0u64, ZERO_HASH.to_string());
        if path.exists() {
            let f = File::open(path)?;
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                if let Ok(rec) = serde_json::from_str::<AuditRecord>(&line) {
                    seq = rec.seq;
                    last_hash = rec.hash;
                }
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
        Ok(Self {
            inner: Mutex::new(Inner {
                file,
                seq,
                last_hash,
            }),
            path: path.to_path_buf(),
        })
    }

    /// Append a record. Never panics (a poisoned lock or IO error drops ONE
    /// record + logs — the server must stay up; the `seq` gap surfaces the loss).
    pub fn append(&self, action: &str, operator: &str, target: &str, detail: serde_json::Value) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::error!("audit log lock poisoned — record dropped");
                return;
            }
        };
        inner.seq += 1;
        let seq = inner.seq;
        let ts = now_secs();
        let prev = inner.last_hash.clone();
        let detail_json = serde_json::to_string(&detail).unwrap_or_else(|_| "null".into());
        let hash = hash_record(seq, ts, operator, action, target, &detail_json, &prev);
        let rec = AuditRecord {
            seq,
            ts,
            operator: operator.into(),
            action: action.into(),
            target: target.into(),
            detail,
            prev_hash: prev,
            hash: hash.clone(),
        };
        inner.last_hash = hash;
        if let Ok(line) = serde_json::to_string(&rec) {
            if writeln!(inner.file, "{line}").is_err() || inner.file.flush().is_err() {
                tracing::warn!("audit log write failed — record may be lost");
            }
        }
    }

    /// Read + filter + paginate. Re-opens the file fresh (the log is
    /// append-only, so a concurrent writer can only add lines). Newest-first by
    /// default; `?dir=asc` flips it. Hard cap 5000 so a full scan can't OOM.
    pub fn query(&self, q: &AuditQuery) -> std::io::Result<Vec<AuditRecord>> {
        let f = File::open(&self.path)?;
        let reader = BufReader::new(f);
        let mut recs = Vec::new();
        let limit = q.limit.unwrap_or(500).min(5000);
        let offset = q.offset.unwrap_or(0);
        let mut match_count = 0;
        
        for line in reader.lines().map_while(Result::ok) {
            if let Ok(r) = serde_json::from_str::<AuditRecord>(&line) {
                if q.operator.as_deref().is_none_or(|o| r.operator == o)
                    && q.action.as_deref().is_none_or(|a| r.action == a)
                    && q.since.is_none_or(|s| r.ts >= s)
                    && q.until.is_none_or(|u| r.ts <= u)
                {
                    match_count += 1;
                    if q.dir.as_deref() == Some("asc") {
                        if match_count > offset {
                            recs.push(r);
                            if recs.len() >= limit {
                                break;
                            }
                        }
                    } else {
                        recs.push(r);
                    }
                }
            }
        }
        
        if q.dir.as_deref() != Some("asc") {
            recs.reverse();
            let page_offset = offset.min(recs.len());
            recs = recs.into_iter().skip(page_offset).take(limit).collect();
        }
        Ok(recs)
    }

    /// The on-disk log path (for `GET /api/audit/verify`).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Walk the chain; returns `Some(seq)` of the first record whose `hash`
    /// doesn't match the recomputed link (a broken/tampered page), else `None`.
    pub fn verify_chain(path: &Path) -> std::io::Result<Option<u64>> {
        let f = File::open(path)?;
        let mut prev = ZERO_HASH.to_string();
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let rec: AuditRecord = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => return Ok(Some(prev_parse_seq(&line).unwrap_or(0))),
            };
            if rec.prev_hash != prev {
                return Ok(Some(rec.seq));
            }
            let detail_json = serde_json::to_string(&rec.detail).unwrap_or_else(|_| "null".into());
            let recomputed = hash_record(
                rec.seq,
                rec.ts,
                &rec.operator,
                &rec.action,
                &rec.target,
                &detail_json,
                &rec.prev_hash,
            );
            if recomputed != rec.hash {
                return Ok(Some(rec.seq));
            }
            prev = rec.hash;
        }
        Ok(None)
    }
}

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn hash_record(
    seq: u64,
    ts: u64,
    operator: &str,
    action: &str,
    target: &str,
    detail_json: &str,
    prev_hash: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(seq.to_le_bytes());
    h.update(ts.to_le_bytes());
    
    let fields = [operator, action, target, detail_json, prev_hash];
    for f in fields {
        h.update((f.len() as u64).to_le_bytes());
        h.update(f.as_bytes());
    }
    hex::encode(h.finalize())
}

fn prev_parse_seq(line: &str) -> Option<u64> {
    serde_json::from_str::<AuditRecord>(line)
        .ok()
        .map(|r| r.seq)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer() -> (tempfile::TempDir, AuditWriter) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let w = AuditWriter::open(&path).unwrap();
        (dir, w)
    }

    #[test]
    fn append_chains_and_persists() {
        let (dir, w) = writer();
        w.append("task", "alice", "aabb", serde_json::json!({"cmd": "shell"}));
        w.append("task", "bob", "ccdd", serde_json::json!({"cmd": "ls"}));
        let recs = w.query(&AuditQuery::default()).unwrap();
        assert_eq!(recs.len(), 2);
        // newest-first: bob (seq 2) then alice (seq 1)
        assert_eq!(recs[0].operator, "bob");
        assert_eq!(recs[0].seq, 2);
        assert_eq!(recs[1].prev_hash, ZERO_HASH); // first record
        assert_eq!(recs[0].prev_hash, recs[1].hash); // chained
                                                     // verify clean
        let path = dir.path().join("audit.jsonl");
        assert_eq!(AuditWriter::verify_chain(&path).unwrap(), None);
    }

    #[test]
    fn chain_break_detected() {
        let (dir, w) = writer();
        w.append("task", "alice", "x", serde_json::json!({}));
        w.append("task", "bob", "y", serde_json::json!({}));
        // Tamper: rewrite the first line with a forged hash.
        let path = dir.path().join("audit.jsonl");
        let original = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = original.lines().map(String::from).collect();
        // Corrupt the first record's hash field.
        lines[0] = lines[0].replace("\"hash\":\"", "\"hash\":\"ffffff");
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert!(AuditWriter::verify_chain(&path).unwrap().is_some());
    }

    #[test]
    fn query_filters_and_paginates() {
        let (_dir, w) = writer();
        for i in 0..5 {
            w.append(
                "task",
                if i % 2 == 0 { "alice" } else { "bob" },
                &format!("t{i}"),
                serde_json::json!({"i": i}),
            );
        }
        let q = AuditQuery {
            operator: Some("alice".into()),
            limit: Some(2),
            ..Default::default()
        };
        let recs = w.query(&q).unwrap();
        assert_eq!(recs.len(), 2);
        assert!(recs.iter().all(|r| r.operator == "alice"));
    }

    #[test]
    fn recovers_chain_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let w = AuditWriter::open(&path).unwrap();
            w.append("task", "alice", "x", serde_json::json!({}));
        }
        // Reopen — seq continues at 2, prev_hash carries the first record's hash.
        let w = AuditWriter::open(&path).unwrap();
        w.append("task", "bob", "y", serde_json::json!({}));
        let recs = w.query(&AuditQuery::default()).unwrap();
        assert_eq!(recs[0].seq, 2);
        assert_eq!(AuditWriter::verify_chain(&path).unwrap(), None);
    }
}
