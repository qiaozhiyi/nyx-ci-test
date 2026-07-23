//! Session metadata store — SQLite (WAL, ACID) for session persistence.
//!
//! Lives alongside the cred + implant stores in the SAME DB file (each store
//! opens its own `Connection`; SQLite WAL handles the concurrency). Tracks the
//! metadata of every beacon session so the registry SURVIVES a team-server
//! restart: on boot the server reloads these rows into the in-memory `DashMap`,
//! and on each check-in the beacon path upserts (fire-and-forget, off the hot
//! path via a background writer thread) so the row stays current.
//!
//! The in-memory `DashMap` remains the PRIMARY read path — SQLite is the
//! durability layer only. Ephemeral runtime state (the queued pending tasks,
//! the undelivered results buffer, the live `SessionKey`, the send/recv
//! counters) is NOT persisted: those reset on reconnect by design. Session keys
//! stay ephemeral pubkeys, so an implant that reconnects with the same key
//! after a restart finds its session metadata already present.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection};

/// Errors from the session store.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("session-store lock poisoned")]
    Poisoned,
}

pub type Result<T> = std::result::Result<T, SessionStoreError>;

/// Persisted session metadata — one row in the `sessions` table.
///
/// Mirrors the subset of the in-memory `Session` / `SessionInfo` fields needed
/// to (a) repopulate the registry after a restart and (b) show operators the
/// same session list they had before the restart. `session_id` is the hex
/// 32-byte ephemeral pubkey (the registry primary key).
#[derive(Debug, Clone)]
pub struct SessionRecord {
    /// Hex-encoded 32-byte ephemeral implant public key (the registry PK).
    pub session_id: String,
    pub beacon_id: u32,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: u8,
    pub pid: u32,
    pub is_admin: u8,
    /// Unix-epoch seconds of the first check-in (preserved across re-check-ins).
    pub first_seen: u64,
    /// Unix-epoch seconds of the most recent check-in.
    pub last_seen: u64,
    /// One-time auth token presented at check-in, if any (32 bytes). Persisted
    /// only so a reconnecting implant with the same key is recognized; by the
    /// time this is written the token has already been consumed in the
    /// `implants` table, so this is forensic, not auth state.
    pub auth_token: Option<Vec<u8>>,
}

pub struct SessionStore {
    conn: Mutex<Connection>,
    #[allow(dead_code)]
    path: PathBuf,
}

impl SessionStore {
    /// Open (or create) the session store at `path`. Shares the DB file with
    /// the cred + implant stores; SQLite WAL handles concurrent access.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }

    /// In-memory store for tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path: PathBuf::from(":memory:"),
        })
    }

    fn init(conn: &Connection) -> Result<()> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // `CREATE TABLE IF NOT EXISTS` (not gated by schema version) so the
        // table exists after EVERY open regardless of which store opened the
        // shared DB first — each store now tracks its own version in a
        // dedicated table (see `migrate`), so cross-store ordering is a non-issue.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                session_id    TEXT NOT NULL PRIMARY KEY,
                beacon_id     INTEGER NOT NULL,
                hostname      TEXT NOT NULL,
                username      TEXT NOT NULL,
                os            TEXT NOT NULL,
                arch          INTEGER NOT NULL,
                pid           INTEGER NOT NULL,
                is_admin      INTEGER NOT NULL,
                first_seen    INTEGER NOT NULL,
                last_seen     INTEGER NOT NULL,
                auth_token    BLOB
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_last_seen
                ON sessions(last_seen);",
        )?;
        Self::migrate(conn)?;
        Ok(())
    }

    /// Schema-migration gate.
    ///
    /// Each store tracks its own version in a dedicated table
    /// (`_sessions_schema_version`), so migration ordering between the
    /// cred, implant, and session stores (which share one SQLite file)
    /// never races. Each store's baseline table is created idempotently
    /// via `CREATE TABLE IF NOT EXISTS` in its OWN `init`, so baseline
    /// creation NEVER depends on any version number; the version only
    /// gates forward-only `ALTER TABLE` steps added AFTER the baseline.
    /// Append a `if current < N { ALTER ... }` arm here when altering
    /// the `sessions` table post-baseline, and bump
    /// `CURRENT_SCHEMA_VERSION` to match.
    const CURRENT_SCHEMA_VERSION: i64 = 2;


    fn migrate(conn: &Connection) -> Result<()> {
        // CREATE the version table FIRST so the SELECT below never fails
        // against a fresh database.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _sessions_schema_version (
                version INTEGER NOT NULL
            );",
        )?;
        // Seed version 0 for pre-existing databases that lack the row.
        conn.execute(
            "INSERT OR IGNORE INTO _sessions_schema_version (version) VALUES (0);",
            [],
        )?;
        let current: i64 = conn.query_row(
            "SELECT version FROM _sessions_schema_version LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        if current < Self::CURRENT_SCHEMA_VERSION {
            // v0 → v1: baseline (creds/implants tables created by their stores).
            // v1 → v2: session-persistence baseline — the `sessions` table is
            //          created idempotently in `init`, so no ALTER is needed;
            //          this just stamps that this store has run.
            conn.execute(
                "UPDATE _sessions_schema_version SET version = ?1;",
                params![Self::CURRENT_SCHEMA_VERSION],
            )?;
        }
        Ok(())
    }

    /// Upsert a session row. On conflict (same `session_id`) refresh ALL
    /// mutable metadata + bump `last_seen` — a re-check-in from a known implant
    /// overwrites the stale row in place rather than duplicating. The caller
    /// passes the ORIGINAL `first_seen` so the creation time is preserved.
    pub fn upsert(&self, r: &SessionRecord) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| SessionStoreError::Poisoned)?;
        conn.execute(
            "INSERT INTO sessions
             (session_id, beacon_id, hostname, username, os, arch, pid,
              is_admin, first_seen, last_seen, auth_token)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(session_id) DO UPDATE SET
               beacon_id  = excluded.beacon_id,
               hostname   = excluded.hostname,
               username   = excluded.username,
               os         = excluded.os,
               arch       = excluded.arch,
               pid        = excluded.pid,
               is_admin   = excluded.is_admin,
               first_seen = excluded.first_seen,
               last_seen  = excluded.last_seen,
               auth_token = excluded.auth_token",
            params![
                r.session_id,
                r.beacon_id as i64,
                r.hostname,
                r.username,
                r.os,
                r.arch as i64,
                r.pid as i64,
                r.is_admin as i64,
                r.first_seen as i64,
                r.last_seen as i64,
                r.auth_token,
            ],
        )?;
        Ok(())
    }

    /// Bump ONLY `last_seen` for an existing session — the cheap update the
    /// beacon path runs (throttled) between full upserts. Returns `true` if a
    /// row matched (the session is known to the store).
    pub fn touch(&self, session_id: &str, last_seen: u64) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| SessionStoreError::Poisoned)?;
        let n = conn.execute(
            "UPDATE sessions SET last_seen = ?1 WHERE session_id = ?2",
            params![last_seen as i64, session_id],
        )?;
        Ok(n > 0)
    }

    /// All session rows, newest check-in first.
    pub fn list(&self) -> Result<Vec<SessionRecord>> {
        let conn = self.conn.lock().map_err(|_| SessionStoreError::Poisoned)?;
        let mut stmt = conn.prepare(
            "SELECT session_id, beacon_id, hostname, username, os, arch, pid,
                    is_admin, first_seen, last_seen, auth_token
             FROM sessions
             ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], row_to_session)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Delete one session row by hex pubkey. Returns `true` if a row was
    /// removed. The session GC sends a delete when it evicts an idle session so
    /// the persisted store doesn't accumulate dead rows forever.
    pub fn delete(&self, session_id: &str) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| SessionStoreError::Poisoned)?;
        let n = conn.execute(
            "DELETE FROM sessions WHERE session_id = ?1",
            params![session_id],
        )?;
        Ok(n > 0)
    }

    /// Row count — for the boot log ("restored N sessions").
    pub fn count(&self) -> Result<i64> {
        let conn = self.conn.lock().map_err(|_| SessionStoreError::Poisoned)?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))?;
        Ok(n)
    }
}

/// Map a SQL row onto a `SessionRecord`.
fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRecord> {
    Ok(SessionRecord {
        session_id: row.get(0)?,
        beacon_id: row.get::<_, i64>(1)? as u32,
        hostname: row.get(2)?,
        username: row.get(3)?,
        os: row.get(4)?,
        arch: row.get::<_, i64>(5)? as u8,
        pid: row.get::<_, i64>(6)? as u32,
        is_admin: row.get::<_, i64>(7)? as u8,
        first_seen: row.get::<_, i64>(8)? as u64,
        last_seen: row.get::<_, i64>(9)? as u64,
        auth_token: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, host: &str, first_seen: u64) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            beacon_id: 0x1337,
            hostname: host.into(),
            username: "user".into(),
            os: "linux".into(),
            arch: 1,
            pid: 42,
            is_admin: 0,
            first_seen,
            last_seen: first_seen,
            auth_token: Some(vec![0xAB; 32]),
        }
    }

    #[test]
    fn roundtrip_in_memory() {
        let s = SessionStore::open_in_memory().unwrap();
        assert_eq!(s.count().unwrap(), 0);
        s.upsert(&rec("aa", "host-a", 1000)).unwrap();
        s.upsert(&rec("bb", "host-b", 2000)).unwrap();
        assert_eq!(s.count().unwrap(), 2);
        let list = s.list().unwrap();
        assert_eq!(list.len(), 2);
        // newest last_seen first
        assert_eq!(list[0].session_id, "bb");
        assert_eq!(list[1].session_id, "aa");
        let got = &list[0];
        assert_eq!(got.beacon_id, 0x1337);
        assert_eq!(got.arch, 1);
        assert_eq!(got.pid, 42);
        assert_eq!(got.auth_token.as_deref(), Some(&vec![0xABu8; 32][..]));
    }

    #[test]
    fn upsert_updates_in_place_not_duplicate() {
        let s = SessionStore::open_in_memory().unwrap();
        let mut r = rec("aa", "host-a", 1000);
        s.upsert(&r).unwrap();
        // Re-check-in: hostname changed + last_seen advanced; first_seen stays.
        r.hostname = "host-a-renamed".into();
        r.last_seen = 9999;
        // Pass the ORIGINAL first_seen so it is preserved.
        r.first_seen = 1000;
        s.upsert(&r).unwrap();
        assert_eq!(s.count().unwrap(), 1); // no duplicate
        let got = s.list().unwrap().remove(0);
        assert_eq!(got.hostname, "host-a-renamed");
        assert_eq!(got.last_seen, 9999);
        assert_eq!(
            got.first_seen, 1000,
            "first_seen must be preserved on re-upsert"
        );
    }

    #[test]
    fn touch_updates_last_seen_only() {
        let s = SessionStore::open_in_memory().unwrap();
        s.upsert(&rec("aa", "host-a", 1000)).unwrap();
        assert!(
            s.touch("aa", 5555).unwrap(),
            "touch on known session must match"
        );
        let got = s.list().unwrap().remove(0);
        assert_eq!(got.last_seen, 5555);
        assert_eq!(got.first_seen, 1000, "touch must not alter first_seen");
        // Unknown session → no match.
        assert!(!s.touch("nonexistent", 1).unwrap());
    }

    #[test]
    fn delete_returns_flag() {
        let s = SessionStore::open_in_memory().unwrap();
        s.upsert(&rec("aa", "host-a", 1000)).unwrap();
        assert!(s.delete("aa").unwrap());
        assert!(!s.delete("aa").unwrap(), "second delete finds nothing");
        assert_eq!(s.count().unwrap(), 0);
    }

    #[test]
    fn auth_token_null_roundtrips() {
        let s = SessionStore::open_in_memory().unwrap();
        let mut r = rec("aa", "host-a", 1000);
        r.auth_token = None; // legacy implant: no token
        s.upsert(&r).unwrap();
        let got = s.list().unwrap().remove(0);
        assert!(
            got.auth_token.is_none(),
            "NULL auth_token must round-trip as None"
        );
    }

    #[test]
    fn persists_across_reopen_on_disk() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nyx-session-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let s = SessionStore::open(&path).unwrap();
            s.upsert(&rec("persisted", "host-p", 4321)).unwrap();
            assert_eq!(s.count().unwrap(), 1);
        }
        // Reopen the SAME path — the row must survive (the key persistence win).
        let s = SessionStore::open(&path).unwrap();
        assert_eq!(s.count().unwrap(), 1);
        let got = s.list().unwrap().remove(0);
        assert_eq!(got.session_id, "persisted");
        assert_eq!(got.hostname, "host-p");
        assert_eq!(got.first_seen, 4321);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    }

    #[test]
    fn shares_db_file_with_other_stores_without_conflict() {
        // The cred + implant + session stores all open the SAME db file. Ensure
        // opening them in sequence (as main.rs does) leaves all three tables
        // intact and queryable — each store tracks its own schema version in a
        // dedicated table, so there is no migration ordering race.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nyx-shared-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        // Open all three against the same file (order matches a fresh boot).
        let creds = crate::CredStore::open(&path).unwrap();
        let implants = crate::ImplantStore::open(&path).unwrap();
        let sessions = SessionStore::open(&path).unwrap();

        // Write one row to each.
        creds
            .upsert(&crate::CredRecord {
                realm: "R".into(),
                user: "u".into(),
                kind: crate::CredKind::Hash,
                secret: "s".into(),
                source: "t".into(),
                beacon: None,
                collected_at: 1,
                notes: String::new(),
            })
            .unwrap();
        sessions.upsert(&rec("aa", "host", 1)).unwrap();
        drop(implants);

        // Reopen sessions alone — its row (and the creds table) must survive.
        let sessions2 = SessionStore::open(&path).unwrap();
        assert_eq!(
            sessions2.count().unwrap(),
            1,
            "session row must survive reopen"
        );
        assert_eq!(
            creds.count().unwrap(),
            1,
            "creds row must be untouched by session store"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}
