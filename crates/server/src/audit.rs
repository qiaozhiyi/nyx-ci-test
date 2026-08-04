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
//! reveals). Rotation (size cap → `<path>.1` archive, see [`audit_max_bytes`])
//! bounds the ACTIVE file so reads stay bounded; remote shipping is v2.

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
    /// Size cap for the ACTIVE file: `append` rotates when the active file
    /// reaches this many bytes. Set from `NYX_AUDIT_MAX_BYTES` by
    /// [`AuditWriter::open`]; [`AuditWriter::open_with_cap`] injects a fixed
    /// cap so tests can exercise rotation without mutating process-global env.
    cap_bytes: u64,
}

struct Inner {
    file: File,
    seq: u64,
    last_hash: String,
}

/// Size cap for the ACTIVE audit log (tunable via `NYX_AUDIT_MAX_BYTES`,
/// default 64 MiB). When [`AuditWriter::append`] sees the active file at or
/// past this size it rotates: the current file is archived to `<path>.1` and a
/// fresh file is started. Bounding the active file also bounds how much a
/// single `query()` / `verify_chain()` call re-reads (they scan the ACTIVE
/// file) — without rotation an append-only log grows without bound and every
/// request re-scans the whole history.
fn audit_max_bytes() -> u64 {
    std::env::var("NYX_AUDIT_MAX_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64 * 1024 * 1024)
}

/// Rename the active audit log to `<path>.1` (replacing any prior archive) and
/// reopen the active path fresh (create+append). Caller holds the write lock
/// and resets `last_hash` to ZERO_HASH afterwards (the fresh file is a new
/// chain); `seq` is NOT reset, so sequence numbers stay globally unique across
/// rotations.
///
/// Follows the codebase's existing rename-while-open convention (operators.rs
/// `persist`): on Unix the old handle would keep pointing at the ARCHIVED
/// inode, so we MUST replace it with a fresh handle on the active path or
/// subsequent appends would silently land in the archive.
fn rotate(path: &Path, file: &mut File) -> std::io::Result<()> {
    let archive = path.with_extension("jsonl.1");
    // Durable archive: flush the current contents before renaming.
    file.sync_all()?;
    std::fs::rename(path, &archive)?;
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(fresh) => {
            *file = fresh;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(path)?.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
            Ok(())
        }
        Err(e) => {
            // The rename already happened; try to undo it so the handle keeps
            // pointing at the ACTIVE file (a handle follows its inode, so the
            // undo restores consistency). If the undo also fails the handle
            // points at the ARCHIVE: appends land there (data preserved, the
            // active-file contract degrades to query() erroring until restart).
            let _ = std::fs::rename(&archive, path);
            Err(e)
        }
    }
}

impl AuditWriter {
    /// Open (or create) the audit log at `path`. Recovers `seq` + `last_hash`
    /// from existing lines so the hash-chain stays continuous across restart.
    /// The rotation size cap comes from the `NYX_AUDIT_MAX_BYTES` env var
    /// (default 64 MiB) — see [`audit_max_bytes`].
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Self::open_with_cap(path, audit_max_bytes())
    }

    /// Open (or create) the audit log at `path` with an explicit rotation
    /// cap (`cap_bytes`) instead of the process-global `NYX_AUDIT_MAX_BYTES`.
    /// Semantics are identical to [`AuditWriter::open`] except for where the
    /// cap comes from; tests use this to exercise rotation deterministically
    /// without mutating env (which would rotate other parallel tests' logs
    /// mid-flight).
    pub fn open_with_cap(path: &Path, cap_bytes: u64) -> std::io::Result<Self> {
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
            cap_bytes,
        })
    }

    /// Append a record. Never panics (a poisoned lock or IO error drops ONE
    /// record + logs — the server must stay up; the `seq` gap surfaces the loss).
    ///
    /// Rotates the log when the active file exceeds its size cap (the
    /// `NYX_AUDIT_MAX_BYTES` env cap read by [`AuditWriter::open`], or the
    /// cap injected via [`AuditWriter::open_with_cap`]): the
    /// current file is renamed to `<path>.1` (replacing any previous archive)
    /// and a fresh file is started. Rotation bounds what a later `query()` /
    /// `verify_chain()` call re-reads. The chain restarts at ZERO_HASH in the
    /// fresh file (each file carries an intact chain of its own; verify one at
    /// a time — archived records are not queryable through the API). Rotation
    /// is best-effort: on failure we warn and keep appending (the log still
    /// works; only the size bound is deferred).
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
        // Rotate under the lock so rotation is serialized with appends. The
        // fresh file restarts the chain at ZERO_HASH (the archive keeps its
        // own intact chain); `seq` keeps counting so ids stay globally unique.
        if let Ok(meta) = inner.file.metadata() {
            if meta.len() >= self.cap_bytes {
                match rotate(&self.path, &mut inner.file) {
                    Ok(()) => inner.last_hash = ZERO_HASH.to_string(),
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            "audit log rotation failed; continuing to append"
                        );
                    }
                }
            }
        }
        inner.seq += 1;
        let seq = inner.seq;
        let ts = now_secs();
        let detail_json = Self::serialize_detail(&mut detail);
        let rec = Self::chain_link(&mut inner, seq, ts, operator, action, target, detail, &detail_json);
        Self::persist_record(&mut inner.file, &rec);
    }

    /// Serialize detail ONCE; the SAME bytes feed both the hash-chain link
    /// AND the persisted record, so `verify_chain` can never observe a
    /// hash/storage fork (HIGH-4). Previously `detail_json` fell back to
    /// "null" for the hash while `rec.detail` kept the original `Value` —
    /// if that Value then re-serialized to something else, the recomputed
    /// link wouldn't match. Now a serialization failure zeroes `detail` in
    /// BOTH places (hash input + stored record) so they always agree.
    fn serialize_detail(detail: &mut serde_json::Value) -> String {
        match serde_json::to_string(detail) {
            Ok(s) => s,
            Err(_) => {
                *detail = serde_json::Value::Null;
                "null".to_string()
            }
        }
    }

    /// Hash-chain update: compute the link over the record fields, build the
    /// record, and advance `last_hash` to the new link.
    fn chain_link(
        inner: &mut Inner,
        seq: u64,
        ts: u64,
        operator: &str,
        action: &str,
        target: &str,
        detail: serde_json::Value,
        detail_json: &str,
    ) -> AuditRecord {
        let prev = inner.last_hash.clone();
        let hash = hash_record(seq, ts, operator, action, target, detail_json, &prev);
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
        rec
    }

    /// 落盘 flush: write the serialized record and flush per-record (durable
    /// against clean shutdown).
    fn persist_record(file: &mut File, rec: &AuditRecord) {
        if let Ok(line) = serde_json::to_string(rec) {
            if writeln!(file, "{line}").is_err() || file.flush().is_err() {
                tracing::warn!("audit log write failed — record may be lost");
            }
        }
    }

    /// Read + filter + paginate. Re-opens the file fresh (the log is
    /// append-only, so a concurrent writer can only add lines). Newest-first by
    /// default; `?dir=asc` flips it. Hard cap 5000 so a full scan can't OOM.
    ///
    /// The full-file scan is bounded by rotation ([`audit_max_bytes`]): the
    /// ACTIVE file never exceeds the size cap, so a re-read per request is at
    /// most a cap-sized scan (the archived `.1` file is not queryable via the
    /// API — rotate/trim archives by hand to keep them, or they are replaced
    /// on the next rotation).
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
        let (limit, offset, is_asc, keep) = Self::page_params(q);
        Ok(Self::scan_records(reader, q, limit, offset, is_asc, keep))
    }

    /// 过滤条件解析: resolve pagination/direction parameters from the query.
    /// Returns `(limit, offset, is_asc, keep)`. `keep` bounds the ring buffer
    /// for the newest-first path. Cap it at HARD_CAP so an attacker-supplied
    /// `offset` can't grow the buffer unboundedly; an offset beyond the cap
    /// simply yields an empty page.
    fn page_params(q: &AuditQuery) -> (usize, usize, bool, usize) {
        let limit = q.limit.unwrap_or(500).min(HARD_CAP);
        let offset = q.offset.unwrap_or(0);
        let is_asc = q.dir.as_deref() == Some("asc");
        let keep = offset.saturating_add(limit).min(HARD_CAP);
        (limit, offset, is_asc, keep)
    }

    /// 记录扫描: read the file oldest-first, filter, and paginate.
    /// Oldest-first (`asc`) path: collect only the page records, then stop.
    /// Newest-first path: ring buffer of the `keep` newest matches.
    fn scan_records(
        reader: BufReader<File>,
        q: &AuditQuery,
        limit: usize,
        offset: usize,
        is_asc: bool,
        keep: usize,
    ) -> Vec<AuditRecord> {
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
            return asc_recs;
        }
        // Newest-first: the buffer holds the `keep` newest matches in insertion
        // (oldest-first) order. Reverse → newest-first, then skip/take the page.
        ring.into_iter().rev().skip(offset).take(limit).collect()
    }

    /// The on-disk log path (for `GET /api/audit/verify`).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Walk the chain; `Ok(true)` iff every scanned record's `hash` matches
    /// its recomputed link (a clean chain). See [`VerifyError`] for the
    /// failure modes — the old `Option<u64>` sentinels (`Some(0)` for a
    /// malformed line, `Some(u64::MAX)` for the scan cap) are gone.
    ///
    /// Line-count bounded (M-DoS): unlike the read path this used to scan the
    /// ENTIRE audit file with no cap. An attacker who grew `audit.jsonl` to
    /// millions of lines could force a single `GET /api/audit/verify` to burn
    /// unbounded CPU/memory. We cap the scan at `MAX_VERIFY_LINES`: past it the
    /// chain is considered unverifiable from this call and we return
    /// [`VerifyError::Truncated`] (the operator should rotate/trim the log
    /// rather than trust a partial verification).
    pub fn verify_chain(path: &Path) -> Result<bool, VerifyError> {
        let f = File::open(path).map_err(VerifyError::Io)?;
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
                // return "chain intact" (Ok(true)), and there is no single seq
                // to blame. Surface the truncation explicitly instead of a
                // false green light.
                return Err(VerifyError::Truncated { line: line_count });
            }
            prev = Self::verify_record(&line, &prev, line_count)?;
        }
        Ok(true)
    }

    /// 逐条重算/比对: parse one line, check its `prev_hash` link, and recompute
    /// its hash-chain link. Returns the record's hash (the next record's
    /// expected `prev_hash`).
    fn verify_record(line: &str, prev: &str, line_count: usize) -> Result<String, VerifyError> {
        // Malformed line (serde_json failed): previously this fell back to
        // `prev_parse_seq(&line).unwrap_or(0)`, but `prev_parse_seq` ALSO
        // parses via serde_json — so it ALWAYS failed too and returned 0,
        // silently masking the real corruption position with a bogus seq 0.
        // Now surface the corruption explicitly: log the offending line and
        // blame the 1-based line number (the canonical "unparseable"
        // position) so operators see WHERE verification broke instead of a
        // misleading pass/fail.
        let rec: AuditRecord = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => {
                tracing::warn!(line, "audit line malformed during verify");
                return Err(VerifyError::MalformedLine { line: line_count });
            }
        };
        if rec.prev_hash != prev {
            return Err(VerifyError::ChainBreak { seq: rec.seq });
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
            return Err(VerifyError::ChainBreak { seq: rec.seq });
        }
        Ok(rec.hash)
    }
}

/// Outcome of an audit-chain verification. `Err` variants replace the old
/// `Option<u64>` sentinels — `Some(0)` (malformed line) and `Some(u64::MAX)`
/// (scan cap hit) were magic numbers whose meaning callers had to know; the
/// variants below carry the same information explicitly.
#[derive(Debug)]
pub enum VerifyError {
    /// The log could not be read (open/IO failure).
    Io(std::io::Error),
    /// A record's stored `hash` doesn't match the recomputed link — a broken
    /// or tampered middle page. Carries the offending record's `seq`.
    ChainBreak { seq: u64 },
    /// A line failed to parse as a record, so verification cannot continue.
    /// Carries the 1-based line number (the corruption position).
    MalformedLine { line: usize },
    /// The scan hit `MAX_VERIFY_LINES` before EOF — the tail of the log was
    /// NOT verified. Treat as untrusted: rotate/trim the log to verify in full.
    Truncated { line: usize },
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
        assert!(AuditWriter::verify_chain(&path).unwrap());
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
        assert!(matches!(
            AuditWriter::verify_chain(&path),
            Err(VerifyError::ChainBreak { .. })
        ));
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
        assert!(AuditWriter::verify_chain(&path).unwrap());
    }

    /// Rotation archives the over-cap file and starts a FRESH chain: the
    /// active file is renamed to the archive (via `with_extension("jsonl.1")`,
    /// see `rotate`), the active path restarts small, and BOTH files carry
    /// intact hash chains — the archive preserves the pre-rotation chain
    /// (rename, not rewrite), the active file restarts at ZERO_HASH. `seq` is
    /// NOT reset, so ids stay globally unique across the boundary.
    ///
    /// The cap is injected via `open_with_cap` so this test never mutates the
    /// process-global `NYX_AUDIT_MAX_BYTES` (which would rotate other parallel
    /// tests' logs mid-flight).
    #[test]
    fn audit_rotation_archives_and_resets_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        // Mirrors rotate()'s archive naming exactly (audit.log -> audit.jsonl.1).
        let archive = path.with_extension("jsonl.1");
        let cap = 512u64;

        let w = AuditWriter::open_with_cap(&path, cap).unwrap();
        let mut appended = 0u64;
        while !archive.exists() {
            appended += 1;
            assert!(
                appended <= 64,
                "rotation never triggered after {appended} appends (cap {cap}B)"
            );
            w.append(
                "rotate",
                "system",
                "t",
                serde_json::json!({ "n": appended }),
            );
        }

        // Rotation fired: the archive holds the >=cap pre-rotation log; the
        // active file restarted small (only the record that triggered the
        // rotation was written after the fresh open).
        assert!(
            std::fs::metadata(&archive).unwrap().len() >= cap,
            "archive should hold the over-cap pre-rotation log"
        );
        let active_len = std::fs::metadata(&path).unwrap().len();
        assert!(
            active_len < cap,
            "active file must restart small after rotation, got {active_len}B"
        );

        // The fresh ACTIVE file is a new chain: it verifies from ZERO_HASH...
        assert!(
            AuditWriter::verify_chain(&path).unwrap(),
            "active file chain must verify (fresh chain restarting at ZERO_HASH)"
        );
        // ...while the ARCHIVE preserves the pre-rotation chain intact.
        assert!(
            AuditWriter::verify_chain(&archive).unwrap(),
            "archive chain must verify (rename preserves the pre-rotation log)"
        );

        // `seq` is NOT reset across rotation: the active file holds only the
        // post-rotation records, and the newest seq equals the total append
        // count (rotation is the only event that produced the archive).
        let recs = w.query(&AuditQuery::default()).unwrap();
        assert_eq!(
            recs.len(),
            1,
            "active file holds only post-rotation records"
        );
        assert_eq!(
            recs[0].seq, appended,
            "seq must keep counting across rotation"
        );
    }
}
