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
    pub fn append(
        &self,
        action: &str,
        operator: &str,
        target: &str,
        mut detail: serde_json::Value,
    ) {
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
        // Serialize detail ONCE; the SAME bytes feed both the hash-chain link
        // AND the persisted record, so `verify_chain` can never observe a
        // hash/storage fork (HIGH-4). Previously `detail_json` fell back to
        // "null" for the hash while `rec.detail` kept the original `Value` —
        // if that Value then re-serialized to something else, the recomputed
        // link wouldn't match. Now a serialization failure zeroes `detail` in
        // BOTH places (hash input + stored record) so they always agree.
        let detail_json = match serde_json::to_string(&detail) {
            Ok(s) => s,
            Err(_) => {
                detail = serde_json::Value::Null;
                "null".to_string()
            }
        };
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
    ///
    /// Memory bounding (M12): the file is read oldest-first. The oldest-first
    /// (`dir=asc`) output short-circuits as soon as `limit` page records past
    /// `offset` are collected, so it never holds more than `limit` records. The
    /// default newest-first output cannot short-circuit (the newest records come
    /// last), so it uses a ring buffer capped at `keep = offset + limit`
    /// matches: each new match pushes to the back and, once `keep` is exceeded,
    /// the oldest is dropped from the front. After the scan the buffer holds at
    /// most the `keep` newest matches; reversing yields newest-first and
    /// `skip(offset).take(limit)` selects the page. `keep` is itself capped at
    /// `HARD_CAP` so a malicious `offset` can't force a huge buffer — beyond the
    /// cap the page just returns fewer rows.
    pub fn query(&self, q: &AuditQuery) -> std::io::Result<Vec<AuditRecord>> {
        let f = File::open(&self.path)?;
        let reader = BufReader::new(f);
        let limit = q.limit.unwrap_or(500).min(HARD_CAP);
        let offset = q.offset.unwrap_or(0);
        let is_asc = q.dir.as_deref() == Some("asc");
        // `keep` bounds the ring buffer for the newest-first path. Cap it at
        // HARD_CAP so an attacker-supplied `offset` can't grow the buffer
        // unboundedly; an offset beyond the cap simply yields an empty page.
        let keep = offset.saturating_add(limit).min(HARD_CAP);

        // Oldest-first (`asc`) path: collect only the page records, then stop.
        // Newest-first path: ring buffer of the `keep` newest matches.
        let mut asc_recs: Vec<AuditRecord> = Vec::new();
        let mut ring: std::collections::VecDeque<AuditRecord> =
            std::collections::VecDeque::with_capacity(keep.max(1));
        let mut match_count = 0;

        for line in reader.lines().map_while(Result::ok) {
            let Ok(r) = serde_json::from_str::<AuditRecord>(&line) else {
                continue;
            };
            if !(q.operator.as_deref().is_none_or(|o| r.operator == o)
                && q.action.as_deref().is_none_or(|a| r.action == a)
                && q.since.is_none_or(|s| r.ts >= s)
                && q.until.is_none_or(|u| r.ts <= u))
            {
                continue;
            }
            match_count += 1;
            if is_asc {
                if match_count > offset {
                    asc_recs.push(r);
                    if asc_recs.len() >= limit {
                        break;
                    }
                }
            } else {
                // Ring buffer: keep only the `keep` newest matches in memory.
                ring.push_back(r);
                if ring.len() > keep {
                    ring.pop_front();
                }
            }
        }

        if is_asc {
            return Ok(asc_recs);
        }
        // Newest-first: the buffer holds the `keep` newest matches in insertion
        // (oldest-first) order. Reverse → newest-first, then skip/take the page.
        let recs: Vec<AuditRecord> = ring.into_iter().rev().skip(offset).take(limit).collect();
        Ok(recs)
    }

    /// The on-disk log path (for `GET /api/audit/verify`).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Walk the chain; returns `Some(seq)` of the first record whose `hash`
    /// doesn't match the recomputed link (a broken/tampered page), else `None`.
    ///
    /// Line-count bounded (M-DoS): unlike the read path this used to scan the
    /// ENTIRE audit file with no cap. An attacker who grew `audit.jsonl` to
    /// millions of lines could force a single `GET /api/audit/verify` to burn
    /// unbounded CPU/memory. We cap the scan at `MAX_VERIFY_LINES`: past it the
    /// chain is considered unverifiable from this call and we return `None` with
    /// a warning (the operator should rotate/trim the log rather than trust a
    /// partial verification).
    pub fn verify_chain(path: &Path) -> std::io::Result<Option<u64>> {
        let f = File::open(path)?;
        let mut prev = ZERO_HASH.to_string();
        let mut line_count = 0usize;
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            line_count += 1;
            if line_count > MAX_VERIFY_LINES {
                tracing::warn!(
                    line_count,
                    max = MAX_VERIFY_LINES,
                    "audit verify_chain hit MAX_VERIFY_LINES; aborting verification \
                     (rotate/trim the audit log to verify in full)"
                );
                // Treat as untrusted: a truncated verification cannot honestly
                // return "chain intact" (Ok(None)), and we have no single seq to
                // blame. Return u64::MAX as a synthetic "tail not verified"
                // sentinel so the API surfaces a non-clean result instead of a
                // false green light.
                return Ok(Some(u64::MAX));
            }
            // Malformed line (serde_json failed): previously this fell back to
            // `prev_parse_seq(&line).unwrap_or(0)`, but `prev_parse_seq` ALSO
            // parses via serde_json — so it ALWAYS failed too and returned 0,
            // silently masking the real corruption position with a bogus seq 0.
            // Now surface the corruption explicitly: log the offending line and
            // blame seq 0 (the canonical "unparseable" sentinel) so operators
            // see WHERE verification broke instead of a misleading pass/fail.
            let rec: AuditRecord = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => {
                    tracing::warn!(line, "audit line malformed during verify");
                    return Ok(Some(0));
                }
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

/// Upper bound on the number of lines `verify_chain` will scan in one call.
/// Bounds CPU/memory so a multi-million-line audit log (attacker-grown or just
/// long-lived) can't force a single verify request to scan the whole file.
/// `query()` already bounds its read via `HARD_CAP`; this is the verify-path
/// analogue.
const MAX_VERIFY_LINES: usize = 1_000_000;

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Hard cap on the number of records a single `query()` can return (and on the
/// ring-buffer size for the newest-first path). Bounds memory so a full-file
/// scan can't OOM (M12) — an append-only audit log can grow arbitrarily large,
/// and the newest-first pagination previously materialized every match.
const HARD_CAP: usize = 5000;

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
    h.update(8u64.to_le_bytes());
    h.update(seq.to_le_bytes());
    h.update(8u64.to_le_bytes());
    h.update(ts.to_le_bytes());

    let fields = [operator, action, target, detail_json, prev_hash];
    for f in fields {
        h.update((f.len() as u64).to_le_bytes());
        h.update(f.as_bytes());
    }
    hex::encode(h.finalize())
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
