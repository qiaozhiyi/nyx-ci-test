//! The persistent credential store — SQLite (WAL, ACID) behind a `Mutex`.
//!
//! Why SQLite over sled/json-file: a credential vault's #1 requirement is that
//! it survives EVERY team-server restart with zero corruption. SQLite's WAL
//! atomic-commit gives that (a torn write or SIGKILL between commits can never
//! corrupt or truncate the table); sled is unmaintained (last release 2021);
//! the whole-file-rewrite JSON pattern (the old client-local `creds.json`) has
//! the WORST durability — a crash mid-rewrite zeros the vault. See the Phase 2
//! design (`nyx-credstore-design` workflow).
//!
//! Concurrency: `Mutex<Connection>` serializes writes (fine for thousands of
//! creds; a cred store never sees high write rates). Every method returns
//! `Result` — the server runs `panic=abort`, so this layer NEVER panics on bad
//! input/IO/SQL.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::model::{CredKind, CredRecord};

/// Errors from the store. `Poisoned` covers a panicked thread holding the
/// connection lock (shouldn't happen since methods never panic, but the server
/// must stay up regardless).
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cred-store lock poisoned")]
    Poisoned,
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub struct CredStore {
    conn: Mutex<Connection>,
    #[allow(dead_code)]
    path: PathBuf,
}

impl CredStore {
    /// Open (or create) the store at `path`. Sets WAL + synchronous=NORMAL for
    /// crash-safe ACID, creates the schema if absent, and best-effort 0600s the
    /// db file (the team-server disk is a single high-value target).
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        let _ = set_private(path); // best-effort; not fatal
        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }

    /// In-memory store — for `AppState::default()` (tests) + unit tests. Never
    /// touches disk.
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
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS creds (
                realm        TEXT NOT NULL,
                user         TEXT NOT NULL,
                kind         TEXT NOT NULL,
                secret       TEXT NOT NULL,
                source       TEXT NOT NULL DEFAULT '',
                beacon       TEXT,
                collected_at INTEGER NOT NULL DEFAULT 0,
                notes        TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (realm, user, kind)
            );",
        )?;
        Self::migrate(conn)?;
        Ok(())
    }

    /// Lightweight schema-migration gate.
    ///
    /// Each store tracks its own version in a dedicated table
    /// (`_creds_schema_version`) so that migration ordering between the
    /// cred, session, and implant stores (which share one SQLite file)
    /// never races. Bump `CURRENT_SCHEMA_VERSION` and append a migration
    /// arm when adding columns or altering tables — `ALTER TABLE ...
    /// ADD COLUMN` is the forward-only pattern SQLite supports without a
    /// full reload.
    const CURRENT_SCHEMA_VERSION: i64 = 1;

    fn migrate(conn: &Connection) -> Result<()> {
        // CREATE the version table FIRST so the SELECT below never fails
        // against a fresh database.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _creds_schema_version (
                version INTEGER NOT NULL
            );",
        )?;
        // Seed version 0 for pre-existing databases that lack the row.
        conn.execute(
            "INSERT OR IGNORE INTO _creds_schema_version (version) VALUES (0);",
            [],
        )?;
        let current: i64 = conn.query_row(
            "SELECT version FROM _creds_schema_version LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        if current < Self::CURRENT_SCHEMA_VERSION {
            // --- migration arms (forward-only) ---------------------------------
            // v0 → v1: initial baseline (creds table already created by init).
            //         No ALTER needed — this just stamps the version.
            // if current < 1 {
            //     conn.execute("ALTER TABLE creds ADD COLUMN ...", [])?;
            // }
            conn.execute(
                "UPDATE _creds_schema_version SET version = ?1;",
                params![Self::CURRENT_SCHEMA_VERSION],
            )?;
        }
        Ok(())
    }

    /// Upsert (CS-parity: same `(realm,user,kind)` updates the secret in place
    /// rather than appending a duplicate — a re-dump after a password change
    /// overwrites the old secret).
    pub fn upsert(&self, r: &CredRecord) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        conn.execute(
            "INSERT INTO creds (realm, user, kind, secret, source, beacon, collected_at, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(realm, user, kind) DO UPDATE SET
               secret       = excluded.secret,
               source       = excluded.source,
               beacon       = excluded.beacon,
               collected_at = excluded.collected_at,
               notes        = excluded.notes",
            params![
                r.realm,
                r.user,
                r.kind.label(),
                r.secret,
                r.source,
                r.beacon,
                r.collected_at as i64,
                r.notes,
            ],
        )?;
        Ok(())
    }

    /// All records (cleartext). The caller masks secrets for list/preview.
    pub fn list(&self) -> Result<Vec<CredRecord>> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let mut stmt = conn.prepare(
            "SELECT realm, user, kind, secret, source, beacon, collected_at, notes FROM creds",
        )?;
        let rows = stmt.query_map([], row_to_record)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// One record by key (cleartext), or `None`.
    pub fn get(&self, realm: &str, user: &str, kind: CredKind) -> Result<Option<CredRecord>> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let mut stmt = conn.prepare(
            "SELECT realm, user, kind, secret, source, beacon, collected_at, notes
             FROM creds WHERE realm = ?1 AND user = ?2 AND kind = ?3",
        )?;
        let mut rows = stmt.query_map(params![realm, user, kind.label()], row_to_record)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Delete one record by key. Returns `true` if a row was removed.
    pub fn delete(&self, realm: &str, user: &str, kind: CredKind) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let n = conn.execute(
            "DELETE FROM creds WHERE realm = ?1 AND user = ?2 AND kind = ?3",
            params![realm, user, kind.label()],
        )?;
        Ok(n > 0)
    }

    /// Row count — for the boot log ("restored N credentials").
    pub fn count(&self) -> Result<i64> {
        let conn = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM creds", [], |row| row.get(0))?;
        Ok(n)
    }
}

/// Map a SQL row onto a `CredRecord`. `kind` is written by this crate only, so
/// `from_label` always resolves; a hand-corrupted label defaults to `Hash`
/// rather than failing the whole list (the row still loads).
fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<CredRecord> {
    let kind_str: String = row.get(2)?;
    let kind = CredKind::from_label(&kind_str).unwrap_or(CredKind::Hash);
    Ok(CredRecord {
        realm: row.get(0)?,
        user: row.get(1)?,
        kind,
        secret: row.get(3)?,
        source: row.get(4)?,
        beacon: row.get(5)?,
        collected_at: row.get::<_, i64>(6)? as u64,
        notes: row.get(7)?,
    })
}

/// Best-effort `chmod 0600` (Unix only). Non-fatal — the store still opens.
#[cfg(unix)]
fn set_private(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_private(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(realm: &str, user: &str, secret: &str) -> CredRecord {
        CredRecord {
            realm: realm.into(),
            user: user.into(),
            kind: CredKind::Hash,
            secret: secret.into(),
            source: "test".into(),
            beacon: None,
            collected_at: 1_700_000_000,
            notes: String::new(),
        }
    }

    #[test]
    fn roundtrip_in_memory() {
        let s = CredStore::open_in_memory().unwrap();
        assert_eq!(s.count().unwrap(), 0);
        s.upsert(&rec("DEV", "alice", "deadbeef")).unwrap();
        s.upsert(&rec("DEV", "bob", "cafef00d")).unwrap();
        assert_eq!(s.count().unwrap(), 2);
        let got = s.get("DEV", "alice", CredKind::Hash).unwrap().unwrap();
        assert_eq!(got.secret, "deadbeef");
    }

    #[test]
    fn upsert_updates_in_place_not_duplicate() {
        let s = CredStore::open_in_memory().unwrap();
        s.upsert(&rec("DEV", "alice", "oldhash")).unwrap();
        s.upsert(&rec("DEV", "alice", "newhash")).unwrap();
        assert_eq!(s.count().unwrap(), 1); // no duplicate
        assert_eq!(
            s.get("DEV", "alice", CredKind::Hash)
                .unwrap()
                .unwrap()
                .secret,
            "newhash"
        );
    }

    #[test]
    fn delete_returns_flag() {
        let s = CredStore::open_in_memory().unwrap();
        s.upsert(&rec("DEV", "alice", "h")).unwrap();
        assert!(s.delete("DEV", "alice", CredKind::Hash).unwrap());
        assert!(!s.delete("DEV", "alice", CredKind::Hash).unwrap()); // already gone
        assert_eq!(s.count().unwrap(), 0);
    }

    #[test]
    fn persists_across_reopen_on_disk() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nyx-store-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        // clean wal/shm siblings too
        {
            let s = CredStore::open(&path).unwrap();
            s.upsert(&rec("DEV", "alice", "persisted")).unwrap();
        }
        // Reopen the SAME path — the row must survive (the key Phase 2 win).
        let s = CredStore::open(&path).unwrap();
        assert_eq!(s.count().unwrap(), 1);
        assert_eq!(
            s.get("DEV", "alice", CredKind::Hash)
                .unwrap()
                .unwrap()
                .secret,
            "persisted"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}
