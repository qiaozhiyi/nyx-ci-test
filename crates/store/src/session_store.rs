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
//! the undelivered results buffer, the live `SessionKey`) is NOT persisted:
//! those reset on reconnect by design. The send/recv frame counters ARE
//! persisted (schema v3, `send_counter`/`last_recv` columns) so a restart can
//! restore anti-replay state; the restored values are advisory — the server
//! re-derives key material on first post-restart check-in. Session keys stay
//! ephemeral pubkeys, so an implant that reconnects with the same key after a
//! restart finds its session metadata already present.

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
    /// Last S2C frame counter sealed for this session (schema v3+).
    pub send_counter: u64,
    /// Highest C2S frame counter received for this session (schema v3+).
    pub last_recv: u64,
    /// SHA-256 of the one-time auth token presented at check-in, if any (32
    /// bytes). The RAW token is never persisted here — the server writes only
    /// the hash (mirroring the `implants` table, which stores the same SHA-256)
    /// so a leaked DB file yields no replayable token material. Restore never
    /// replays it, so this column is forensic, not auth state.
    pub auth_token: Option<Vec<u8>>,
    /// Operator name who owns this session (schema v4+). `None` = unowned.
    /// Set ONLY via `update_owner` — the beacon-path upsert never touches it.
    pub owner: Option<String>,
}

pub struct SessionStore {
    conn: Mutex<Connection>,
    #[allow(dead_code)]
    path: PathBuf,
}

impl SessionStore {
    /// Open (or create) the session store at `path`. Shares the DB file with
    /// the cred + implant stores; SQLite WAL handles concurrent access.
    /// Best-effort 0600s the db file + WAL siblings.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        let _ = crate::set_private(path); // best-effort; not fatal
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
        // Same DB file is shared with the cred/implant stores; make contended
        // writes WAIT (up to 5s) instead of failing with SQLITE_BUSY.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
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
    ///
    /// All arms + the version stamp run inside ONE transaction: the v3 arm
    /// alone issues TWO `ALTER TABLE`s, and a crash between them would leave
    /// the DB half-migrated at the OLD version — the next `open()` would
    /// re-run the first ALTER and die on duplicate-column, permanently
    /// bricking the store. A rollback preserves the pre-migration state so
    /// the next open retries cleanly.
    const CURRENT_SCHEMA_VERSION: i64 = 4;

    fn migrate(conn: &Connection) -> Result<()> {
        // CREATE the version table FIRST so the SELECT below never fails
        // against a fresh database.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _sessions_schema_version (
                version INTEGER NOT NULL
            );",
        )?;
        // Seed version 0 only when the table is empty. The version table has
        // no UNIQUE constraint, so a plain INSERT OR IGNORE would append a
        // stale version=0 row on EVERY open (one per server boot).
        conn.execute(
            "INSERT INTO _sessions_schema_version (version) SELECT 0 WHERE NOT EXISTS \
             (SELECT 1 FROM _sessions_schema_version);",
            [],
        )?;
        // MAX() so the gate never depends on unspecified rowid scan order.
        let current: i64 = conn.query_row(
            "SELECT MAX(version) FROM _sessions_schema_version",
            [],
            |r| r.get(0),
        )?;
        if current < Self::CURRENT_SCHEMA_VERSION {
            let tx = conn.unchecked_transaction()?;
            // v0 → v1: baseline (creds/implants tables created by their stores).
            // v1 → v2: session-persistence baseline — the `sessions` table is
            //          created idempotently in `init`, so no ALTER is needed;
            //          this just stamps that this store has run.
            // v2 → v3: persist per-session frame counters. `DEFAULT 0`
            //          backfills existing rows, so old rows stay compatible
            //          (read back with counters 0). NOTE: do NOT add these to
            //          the baseline CREATE TABLE in `init` — a fresh DB starts
            //          at version 0 and runs this arm, so the columns must
            //          exist only AFTER the ALTER (adding them to the CREATE
            //          would make this arm fail with duplicate-column).
            if current < 3 {
                tx.execute(
                    "ALTER TABLE sessions ADD COLUMN send_counter INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
                tx.execute(
                    "ALTER TABLE sessions ADD COLUMN last_recv INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
            }
            // v3 → v4: operator ownership of a session. `DEFAULT NULL`
            // backfills existing rows as unowned.
            if current < 4 {
                tx.execute("ALTER TABLE sessions ADD COLUMN owner TEXT", [])?;
            }
            tx.execute(
                "UPDATE _sessions_schema_version SET version = ?1;",
                params![Self::CURRENT_SCHEMA_VERSION],
            )?;
            tx.commit()?;
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
              is_admin, first_seen, last_seen, auth_token,
              send_counter, last_recv)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(session_id) DO UPDATE SET
               beacon_id    = excluded.beacon_id,
               hostname     = excluded.hostname,
               username     = excluded.username,
               os           = excluded.os,
               arch         = excluded.arch,
               pid          = excluded.pid,
               is_admin     = excluded.is_admin,
               first_seen   = excluded.first_seen,
               last_seen    = excluded.last_seen,
               auth_token   = excluded.auth_token,
               send_counter = excluded.send_counter,
               last_recv    = excluded.last_recv",
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
                r.send_counter as i64,
                r.last_recv as i64,
            ],
        )?;
        Ok(())
    }

    /// Persist ONLY the per-session frame counters — the cheap per-frame
    /// update the server runs after each sealed/decoded frame (the hot path;
    /// `upsert` would rewrite every metadata column). Returns `true` if a row
    /// matched. Unknown session → `Ok(false)` (caller decides; the server
    /// treats it as best-effort).
    pub fn update_counters(
        &self,
        session_id: &str,
        send_counter: u64,
        last_recv: u64,
    ) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| SessionStoreError::Poisoned)?;
        let n = conn.execute(
            "UPDATE sessions SET send_counter = ?1, last_recv = ?2 WHERE session_id = ?3",
            params![send_counter as i64, last_recv as i64, session_id],
        )?;
        Ok(n > 0)
    }

    /// Set (or clear, with `None`) the operator who owns a session. Returns
    /// `true` if a row matched. This is the ONLY writer of the `owner` column
    /// — the beacon-path upsert deliberately leaves it untouched so a check-in
    /// can never clobber operator assignment.
    pub fn update_owner(&self, session_id: &str, owner: Option<&str>) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| SessionStoreError::Poisoned)?;
        let n = conn.execute(
            "UPDATE sessions SET owner = ?1 WHERE session_id = ?2",
            params![owner, session_id],
        )?;
        Ok(n > 0)
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
                    is_admin, first_seen, last_seen, auth_token,
                    send_counter, last_recv, owner
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
        send_counter: row.get::<_, i64>(11)? as u64,
        last_recv: row.get::<_, i64>(12)? as u64,
        owner: row.get(13)?,
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
            send_counter: 0,
            last_recv: 0,
            auth_token: Some(vec![0xAB; 32]),
            owner: None,
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
    fn counters_roundtrip_through_upsert() {
        let s = SessionStore::open_in_memory().unwrap();
        let mut r = rec("aa", "host-a", 1000);
        r.send_counter = 41;
        r.last_recv = 17;
        s.upsert(&r).unwrap();

        let got = s.list().unwrap().remove(0);
        assert_eq!(got.send_counter, 41);
        assert_eq!(got.last_recv, 17);
    }

    #[test]
    fn owner_roundtrip_and_upsert_never_clobbers() {
        let s = SessionStore::open_in_memory().unwrap();
        let mut r = rec("aa", "host-a", 1000);
        r.owner = Some("alice".into());
        s.upsert(&r).unwrap();
        // The beacon-path upsert deliberately does NOT write owner — an
        // in-memory record without owner must not clear an assigned one.
        let mut r2 = rec("aa", "host-a", 1001);
        r2.owner = None;
        s.upsert(&r2).unwrap();
        assert_eq!(s.list().unwrap().remove(0).owner.as_deref(), None);
        // The dedicated update_owner is the only writer.
        assert!(s.update_owner("aa", Some("bob")).unwrap());
        assert_eq!(s.list().unwrap().remove(0).owner.as_deref(), Some("bob"));
        assert!(s.update_owner("aa", None).unwrap());
        assert_eq!(s.list().unwrap().remove(0).owner, None);
        // Unknown session → Ok(false).
        assert!(!s.update_owner("nonexistent", Some("x")).unwrap());
    }

    #[test]
    fn update_counters_persists_and_reports_match() {
        let s = SessionStore::open_in_memory().unwrap();
        s.upsert(&rec("aa", "host-a", 1000)).unwrap();

        assert!(s.update_counters("aa", 7, 9).unwrap());
        let got = s.list().unwrap().remove(0);
        assert_eq!((got.send_counter, got.last_recv), (7, 9));
        // Other columns untouched.
        assert_eq!(got.hostname, "host-a");
        assert_eq!(got.last_seen, 1000);
        // Unknown session → Ok(false), no error.
        assert!(!s.update_counters("nonexistent", 1, 1).unwrap());
    }

    #[test]
    fn migrates_v2_sessions_table_adding_counters() {
        // Simulate a pre-counter database: hand-build the v2 table shape, stamp
        // _sessions_schema_version = 2, insert a row — then let open() run the
        // v2 → v3 migration. Old rows must come back with counters defaulted to
        // 0 (old rows stay compatible), and the store must be writable.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "nyx-session-migrate-test-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE sessions (
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
                CREATE TABLE _sessions_schema_version (version INTEGER NOT NULL);
                INSERT INTO _sessions_schema_version (version) VALUES (2);
                INSERT INTO sessions (session_id, beacon_id, hostname, username, os,
                                      arch, pid, is_admin, first_seen, last_seen)
                VALUES ('legacy-id', 7, 'legacy-host', 'legacy-user', 'linux',
                        1, 42, 0, 1000, 2000);",
            )
            .unwrap();
        }
        let s = SessionStore::open(&path).unwrap();
        let got = s.list().unwrap().remove(0);
        assert_eq!(got.session_id, "legacy-id");
        assert_eq!(got.send_counter, 0, "old rows must backfill DEFAULT 0");
        assert_eq!(got.last_recv, 0);
        // The migrated store persists counters fine.
        assert!(s.update_counters("legacy-id", 7, 9).unwrap());
        let got = s.list().unwrap().remove(0);
        assert_eq!((got.send_counter, got.last_recv), (7, 9));
        // Version must be stamped to the current version after the migration.
        let v: i64 = {
            let conn = Connection::open(&path).unwrap();
            conn.query_row("SELECT version FROM _sessions_schema_version", [], |r| {
                r.get(0)
            })
            .unwrap()
        };
        assert_eq!(v, SessionStore::CURRENT_SCHEMA_VERSION);
        // v4 adds the owner column: legacy rows restore as unowned.
        assert_eq!(got.owner, None);
        // The owner column is writable on migrated rows.
        assert!(s.update_owner("legacy-id", Some("alice")).unwrap());
        assert_eq!(s.list().unwrap().remove(0).owner.as_deref(), Some("alice"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn migrates_v0_sessions_db_without_version_table() {
        // The oldest possible sessions DB (commit 841ffc5 era, before
        // per-store version tables existed): the `sessions` table in its
        // pre-counter shape and NO `_sessions_schema_version` at all. open()
        // must seed version 0 and run EVERY arm (v0 → v4) in one shot:
        // counters + owner backfilled, fixture row preserved, store writable.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "nyx-session-migrate-v0-test-{}.db",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE sessions (
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
                INSERT INTO sessions (session_id, beacon_id, hostname, username, os,
                                      arch, pid, is_admin, first_seen, last_seen)
                VALUES ('v0-id', 9, 'v0-host', 'v0-user', 'windows',
                        1, 4242, 1, 500, 600);",
            )
            .unwrap();
        }
        let s = SessionStore::open(&path).unwrap();
        let got = s.list().unwrap().remove(0);
        assert_eq!(got.session_id, "v0-id");
        assert_eq!(got.pid, 4242, "fixture row must survive the v0 → v4 jump");
        assert_eq!((got.send_counter, got.last_recv), (0, 0));
        assert_eq!(got.owner, None);
        // All arms committed: version stamped straight to CURRENT, exactly once.
        let (v, n): (i64, i64) = {
            let conn = s.conn.lock().unwrap();
            let v = conn
                .query_row(
                    "SELECT MAX(version) FROM _sessions_schema_version",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let n = conn
                .query_row("SELECT COUNT(*) FROM _sessions_schema_version", [], |r| {
                    r.get(0)
                })
                .unwrap();
            (v, n)
        };
        assert_eq!(v, SessionStore::CURRENT_SCHEMA_VERSION);
        assert_eq!(n, 1);
        // Migrated row accepts both v3+ and v4+ writers.
        assert!(s.update_counters("v0-id", 3, 4).unwrap());
        assert!(s.update_owner("v0-id", Some("op")).unwrap());
        let got = s.list().unwrap().remove(0);
        assert_eq!((got.send_counter, got.last_recv), (3, 4));
        assert_eq!(got.owner.as_deref(), Some("op"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn fresh_db_lands_at_current_version_and_reopen_is_idempotent() {
        let s = SessionStore::open_in_memory().unwrap();
        {
            let conn = s.conn.lock().unwrap();
            let v: i64 = conn
                .query_row(
                    "SELECT MAX(version) FROM _sessions_schema_version",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(v, SessionStore::CURRENT_SCHEMA_VERSION);
        }
        // Re-run the migration gate (what a second open() does): must be a
        // no-op — no duplicate ALTER attempt, no extra version row.
        SessionStore::migrate(&s.conn.lock().unwrap()).unwrap();
        let conn = s.conn.lock().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM _sessions_schema_version", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 1, "reopen must not append stale version rows");
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
