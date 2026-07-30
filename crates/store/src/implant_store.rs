//! Implant/payload store — SQLite (WAL, ACID) for generated implant tracking.
//!
//! Lives alongside the cred store in the same DB file. Tracks every generated
//! implant: its per-implant X25519 keypair, one-time auth token, callback config,
//! features, and revocation state. The server beacon handler queries this table
//! on first check-in to validate auth tokens.
//!
//! Concurrency: `Mutex<Connection>` (same pattern as CredStore). Low write rate
//! (implants are generated infrequently); serialized access is fine.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection};

/// Errors from the implant store.
#[derive(Debug, thiserror::Error)]
pub enum ImplantStoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("implant-store lock poisoned")]
    Poisoned,
}

pub type Result<T> = std::result::Result<T, ImplantStoreError>;

/// A generated implant record — one row in the `implants` table.
#[derive(Debug, Clone)]
pub struct ImplantRecord {
    pub id: i64,
    /// Hex-encoded X25519 public key of the per-implant keypair.
    pub implant_pub: String,
    /// SHA-256(auth_token) — never stores the raw token.
    pub auth_token_hash: String,
    /// 0 = fresh (not yet used), 1 = consumed.
    pub auth_token_used: bool,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// Operator username who generated this implant.
    pub created_by: Option<String>,
    /// ISO 8601 expiry, or None = no expiry.
    pub expires_at: Option<String>,
    /// Callback host (IP or hostname).
    pub callback_host: String,
    /// Callback port.
    pub callback_port: u16,
    /// Output format: "dll", "shellcode", "exe".
    pub format: String,
    /// Features bitmap.
    pub features_bitmap: u32,
    /// Number of HKDF environment keying layers.
    pub keying_levels: u32,
    /// Hex-encoded SHA-256 of the output binary.
    pub sha256: String,
    /// Size of the output binary in bytes.
    pub size_bytes: i64,
    /// 0 = active, 1 = revoked.
    pub revoked: bool,
    /// Operator notes.
    pub notes: Option<String>,
}

pub struct ImplantStore {
    conn: Mutex<Connection>,
    #[allow(dead_code)]
    path: PathBuf,
}

impl ImplantStore {
    /// Open (or create) the implant store at `path`. Uses the same DB file as
    /// the cred store — SQLite WAL handles concurrent access.
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
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS implants (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                implant_pub     TEXT NOT NULL UNIQUE,
                auth_token_hash TEXT NOT NULL,
                auth_token_used INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT NOT NULL,
                created_by      TEXT,
                expires_at      TEXT,
                callback_host   TEXT NOT NULL,
                callback_port   INTEGER NOT NULL,
                format          TEXT NOT NULL DEFAULT 'dll',
                features_bitmap INTEGER NOT NULL DEFAULT 0,
                keying_levels   INTEGER NOT NULL DEFAULT 0,
                sha256          TEXT NOT NULL,
                size_bytes      INTEGER NOT NULL,
                revoked         INTEGER NOT NULL DEFAULT 0,
                notes           TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_implants_pub
                ON implants(implant_pub);
            CREATE INDEX IF NOT EXISTS idx_implants_token
                ON implants(auth_token_hash);
            CREATE INDEX IF NOT EXISTS idx_implants_created
                ON implants(created_at);",
        )?;
        Self::migrate(conn)?;
        Ok(())
    }

    /// Schema-migration gate (see `store::Store::migrate` for rationale).
    const CURRENT_SCHEMA_VERSION: i64 = 1;

    fn migrate(conn: &Connection) -> Result<()> {
        // CREATE the version table FIRST so the SELECT below never fails
        // against a fresh database.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _implants_schema_version (
                version INTEGER NOT NULL
            );",
        )?;
        conn.execute(
            "INSERT OR IGNORE INTO _implants_schema_version (version) VALUES (0);",
            [],
        )?;
        let current: i64 = conn.query_row(
            "SELECT version FROM _implants_schema_version LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        if current < Self::CURRENT_SCHEMA_VERSION {
            // v0 → v1: baseline (implants table already created above).
            conn.execute(
                "UPDATE _implants_schema_version SET version = ?1;",
                params![Self::CURRENT_SCHEMA_VERSION],
            )?;
        }
        Ok(())
    }

    /// Insert a new implant record. Returns the auto-incremented id.
    pub fn insert(&self, r: &ImplantRecord) -> Result<i64> {
        let conn = self.conn.lock().map_err(|_| ImplantStoreError::Poisoned)?;
        conn.execute(
            "INSERT INTO implants
             (implant_pub, auth_token_hash, auth_token_used, created_at,
              created_by, expires_at, callback_host, callback_port,
              format, features_bitmap, keying_levels, sha256, size_bytes,
              revoked, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                r.implant_pub,
                r.auth_token_hash,
                r.auth_token_used as i32,
                r.created_at,
                r.created_by,
                r.expires_at,
                r.callback_host,
                r.callback_port,
                r.format,
                r.features_bitmap,
                r.keying_levels,
                r.sha256,
                r.size_bytes,
                r.revoked as i32,
                r.notes,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Look up an implant by auth_token_hash. Returns the record if found and
    /// the token has NOT been used AND the implant is NOT revoked.
    pub fn get_by_token_hash(&self, token_hash: &str) -> Result<Option<ImplantRecord>> {
        let conn = self.conn.lock().map_err(|_| ImplantStoreError::Poisoned)?;
        let mut stmt = conn.prepare(
            "SELECT id, implant_pub, auth_token_hash, auth_token_used,
                    created_at, created_by, expires_at, callback_host,
                    callback_port, format, features_bitmap, keying_levels,
                    sha256, size_bytes, revoked, notes
             FROM implants
             WHERE auth_token_hash = ?1
               AND auth_token_used = 0
               AND revoked = 0",
        )?;
        let mut rows = stmt.query_map(params![token_hash], row_to_implant)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Mark an auth token as used (first check-in consumed it).
    /// Returns true if a row was updated.
    pub fn mark_token_used(&self, implant_pub: &str) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| ImplantStoreError::Poisoned)?;
        let n = conn.execute(
            "UPDATE implants SET auth_token_used = 1 WHERE implant_pub = ?1",
            params![implant_pub],
        )?;
        Ok(n > 0)
    }

    /// Look up an implant by its hex-encoded public key.
    pub fn get_by_pubkey(&self, implant_pub: &str) -> Result<Option<ImplantRecord>> {
        let conn = self.conn.lock().map_err(|_| ImplantStoreError::Poisoned)?;
        let mut stmt = conn.prepare(
            "SELECT id, implant_pub, auth_token_hash, auth_token_used,
                    created_at, created_by, expires_at, callback_host,
                    callback_port, format, features_bitmap, keying_levels,
                    sha256, size_bytes, revoked, notes
             FROM implants WHERE implant_pub = ?1",
        )?;
        let mut rows = stmt.query_map(params![implant_pub], row_to_implant)?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// List all implants, newest first.
    pub fn list(&self) -> Result<Vec<ImplantRecord>> {
        let conn = self.conn.lock().map_err(|_| ImplantStoreError::Poisoned)?;
        let mut stmt = conn.prepare(
            "SELECT id, implant_pub, auth_token_hash, auth_token_used,
                    created_at, created_by, expires_at, callback_host,
                    callback_port, format, features_bitmap, keying_levels,
                    sha256, size_bytes, revoked, notes
             FROM implants
             ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_implant)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Revoke an implant by pubkey. Returns true if a row was updated.
    pub fn revoke(&self, implant_pub: &str) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| ImplantStoreError::Poisoned)?;
        let n = conn.execute(
            "UPDATE implants SET revoked = 1 WHERE implant_pub = ?1",
            params![implant_pub],
        )?;
        Ok(n > 0)
    }

    /// Count total implants.
    pub fn count(&self) -> Result<i64> {
        let conn = self.conn.lock().map_err(|_| ImplantStoreError::Poisoned)?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM implants", [], |row| row.get(0))?;
        Ok(n)
    }

    /// Delete an implant record by pubkey (for testing / admin cleanup).
    pub fn delete_by_pubkey(&self, implant_pub: &str) -> Result<bool> {
        let conn = self.conn.lock().map_err(|_| ImplantStoreError::Poisoned)?;
        let n = conn.execute(
            "DELETE FROM implants WHERE implant_pub = ?1",
            params![implant_pub],
        )?;
        Ok(n > 0)
    }
}

fn row_to_implant(row: &rusqlite::Row<'_>) -> rusqlite::Result<ImplantRecord> {
    Ok(ImplantRecord {
        id: row.get(0)?,
        implant_pub: row.get(1)?,
        auth_token_hash: row.get(2)?,
        auth_token_used: row.get::<_, i32>(3)? != 0,
        created_at: row.get(4)?,
        created_by: row.get(5)?,
        expires_at: row.get(6)?,
        callback_host: row.get(7)?,
        callback_port: row.get::<_, i32>(8)? as u16,
        format: row.get(9)?,
        features_bitmap: row.get::<_, i32>(10)? as u32,
        keying_levels: row.get::<_, i32>(11)? as u32,
        sha256: row.get(12)?,
        size_bytes: row.get(13)?,
        revoked: row.get::<_, i32>(14)? != 0,
        notes: row.get(15)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn test_record(pubkey: &str, token: &[u8]) -> ImplantRecord {
        let mut hasher = Sha256::new();
        hasher.update(token);
        let token_hash = hex::encode(hasher.finalize());

        let mut hasher2 = Sha256::new();
        hasher2.update(b"dummy binary");
        let sha256 = hex::encode(hasher2.finalize());

        ImplantRecord {
            id: 0, // auto-incremented
            implant_pub: pubkey.into(),
            auth_token_hash: token_hash,
            auth_token_used: false,
            created_at: "2026-07-12T00:00:00Z".into(),
            created_by: Some("operator1".into()),
            expires_at: None,
            callback_host: "127.0.0.1".into(),
            callback_port: 8443,
            format: "dll".into(),
            features_bitmap: 0x0F,
            keying_levels: 0,
            sha256,
            size_bytes: 123456,
            revoked: false,
            notes: None,
        }
    }

    #[test]
    fn insert_and_get_by_pubkey() {
        let s = ImplantStore::open_in_memory().unwrap();
        assert_eq!(s.count().unwrap(), 0);

        let rec = test_record("abcd1234", b"token-1");
        let id = s.insert(&rec).unwrap();
        assert!(id > 0);

        let got = s.get_by_pubkey("abcd1234").unwrap().unwrap();
        assert_eq!(got.implant_pub, "abcd1234");
        assert_eq!(got.callback_host, "127.0.0.1");
        assert!(!got.auth_token_used);
        assert!(!got.revoked);
    }

    #[test]
    fn get_by_token_hash_finds_fresh_token() {
        let s = ImplantStore::open_in_memory().unwrap();
        let token = b"secret-token-42";
        let mut hasher = Sha256::new();
        hasher.update(token);
        let token_hash = hex::encode(hasher.finalize());

        let rec = test_record("pubkey1", token);
        s.insert(&rec).unwrap();

        let found = s.get_by_token_hash(&token_hash).unwrap().unwrap();
        assert_eq!(found.implant_pub, "pubkey1");
    }

    #[test]
    fn get_by_token_hash_rejects_used_token() {
        let s = ImplantStore::open_in_memory().unwrap();
        let token = b"used-token";
        let mut hasher = Sha256::new();
        hasher.update(token);
        let token_hash = hex::encode(hasher.finalize());

        let rec = test_record("pubkey2", token);
        s.insert(&rec).unwrap();

        // First lookup finds it
        assert!(s.get_by_token_hash(&token_hash).unwrap().is_some());

        // Mark as used
        s.mark_token_used("pubkey2").unwrap();

        // Now it should NOT be found
        assert!(s.get_by_token_hash(&token_hash).unwrap().is_none());
    }

    #[test]
    fn get_by_token_hash_rejects_revoked() {
        let s = ImplantStore::open_in_memory().unwrap();
        let token = b"revoked-token";
        let mut hasher = Sha256::new();
        hasher.update(token);
        let token_hash = hex::encode(hasher.finalize());

        let rec = test_record("pubkey3", token);
        s.insert(&rec).unwrap();

        s.revoke("pubkey3").unwrap();

        // Revoked implant's token should not be found
        assert!(s.get_by_token_hash(&token_hash).unwrap().is_none());
    }

    #[test]
    fn mark_token_used_idempotent() {
        let s = ImplantStore::open_in_memory().unwrap();
        let rec = test_record("pubkey4", b"token-4");
        s.insert(&rec).unwrap();

        assert!(s.mark_token_used("pubkey4").unwrap());
        // Second mark should be a no-op (already used), but returns true
        // because the UPDATE matched the row (it just set 1 → 1)
        assert!(s.mark_token_used("pubkey4").unwrap());
    }

    #[test]
    fn list_returns_newest_first() {
        let s = ImplantStore::open_in_memory().unwrap();

        let mut r1 = test_record("pk1", b"t1");
        r1.created_at = "2026-07-12T00:00:00Z".into();
        s.insert(&r1).unwrap();

        let mut r2 = test_record("pk2", b"t2");
        r2.created_at = "2026-07-12T01:00:00Z".into();
        s.insert(&r2).unwrap();

        let list = s.list().unwrap();
        assert_eq!(list.len(), 2);
        // Newest first
        assert_eq!(list[0].implant_pub, "pk2");
        assert_eq!(list[1].implant_pub, "pk1");
    }

    #[test]
    fn revoke_and_verify() {
        let s = ImplantStore::open_in_memory().unwrap();
        let rec = test_record("pk5", b"t5");
        s.insert(&rec).unwrap();

        assert!(!s.get_by_pubkey("pk5").unwrap().unwrap().revoked);
        assert!(s.revoke("pk5").unwrap());
        assert!(s.get_by_pubkey("pk5").unwrap().unwrap().revoked);

        // Revoking again is idempotent
        assert!(s.revoke("pk5").unwrap());
    }

    #[test]
    fn revoke_unknown_returns_false() {
        let s = ImplantStore::open_in_memory().unwrap();
        assert!(!s.revoke("nonexistent").unwrap());
    }

    #[test]
    fn delete_by_pubkey() {
        let s = ImplantStore::open_in_memory().unwrap();
        let rec = test_record("pk6", b"t6");
        s.insert(&rec).unwrap();
        assert_eq!(s.count().unwrap(), 1);

        assert!(s.delete_by_pubkey("pk6").unwrap());
        assert_eq!(s.count().unwrap(), 0);
        assert!(!s.delete_by_pubkey("pk6").unwrap());
    }

    #[test]
    fn unique_pubkey_constraint() {
        let s = ImplantStore::open_in_memory().unwrap();
        let rec1 = test_record("pk7", b"t7");
        s.insert(&rec1).unwrap();

        let mut rec2 = test_record("pk7", b"t8"); // same pubkey
        rec2.sha256 = "different".into();
        // Should fail due to UNIQUE constraint
        let result = s.insert(&rec2);
        assert!(result.is_err());
        assert_eq!(s.count().unwrap(), 1);
    }
}
