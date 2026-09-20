//! The disposable cache store, `cache.sqlite`.
//!
//! Everything here is recoverable. A missing cache is recreated, a corrupt one
//! is thrown away and recreated, and a stale one is simply wrong data that the
//! rest of the system is expected to tolerate.
//!
//! Crucially, a stale cache never bypasses identity or network authentication:
//! cached hints only produce *candidates*, which still have to pass the
//! handshake.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};

use crate::error::{Error, Result};
use crate::identity::NetworkId;

/// Schema version written by this build.
pub const SCHEMA_VERSION: i64 = 1;

/// A cached address hint for one peer in one network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressHint {
    /// Network the hint belongs to.
    pub network_id: NetworkId,
    /// Peer endpoint id, 32 bytes.
    pub endpoint_id: [u8; 32],
    /// Serialised address, currently `ip:<socketaddr>` or `relay:<url>`.
    pub addr: String,
    /// Unix seconds when this hint was last confirmed.
    pub last_seen: i64,
}

/// Why the cache had to be recreated, if it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheOutcome {
    /// Opened normally.
    Opened,
    /// Created because nothing was there.
    Created,
    /// Discarded and recreated. The reason is free of secrets.
    Reset(String),
}

/// The disposable cache store.
#[derive(Debug)]
pub struct CacheStore {
    conn: Connection,
    path: PathBuf,
}

impl CacheStore {
    /// Opens the cache, discarding and recreating it if it is unusable.
    pub fn open_or_reset(path: impl AsRef<Path>) -> Result<(Self, CacheOutcome)> {
        let path = path.as_ref().to_path_buf();
        let existed = path.exists();

        match Self::try_open(&path, existed) {
            Ok(store) => Ok((
                store,
                if existed {
                    CacheOutcome::Opened
                } else {
                    CacheOutcome::Created
                },
            )),
            Err(reason) => {
                tracing::warn!(path = %path.display(), %reason, "discarding unusable cache");
                Self::remove_files(&path);
                let store = Self::try_open(&path, false)
                    .map_err(|err| Error::Storage(format!("cannot recreate cache: {err}")))?;
                Ok((store, CacheOutcome::Reset(reason)))
            }
        }
    }

    fn try_open(path: &Path, check_integrity: bool) -> std::result::Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("cannot create cache directory: {err}"))?;
        }
        let conn = Connection::open(path).map_err(|err| format!("cannot open: {err}"))?;
        super::restrict_path_permissions(path).map_err(|err| format!("{err}"))?;
        super::apply_common_pragmas(&conn).map_err(|err| format!("cannot configure: {err}"))?;

        if check_integrity {
            let integrity: String = conn
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))
                .map_err(|err| format!("integrity check failed: {err}"))?;
            if integrity != "ok" {
                return Err(format!("integrity check reported: {integrity}"));
            }
        }

        let found: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|err| format!("cannot read schema version: {err}"))?;
        if found > SCHEMA_VERSION {
            return Err(format!(
                "cache schema version {found} is newer than {SCHEMA_VERSION}"
            ));
        }
        if found < SCHEMA_VERSION {
            conn.execute_batch(
                "BEGIN;
                 DROP TABLE IF EXISTS address_hints;
                 CREATE TABLE address_hints (
                     network_id  BLOB NOT NULL,
                     endpoint_id BLOB NOT NULL,
                     addr        TEXT NOT NULL,
                     last_seen   INTEGER NOT NULL,
                     PRIMARY KEY (network_id, endpoint_id, addr)
                 );
                 PRAGMA user_version = 1;
                 COMMIT;",
            )
            .map_err(|err| format!("cannot create cache schema: {err}"))?;
        } else {
            conn.query_row("SELECT count(*) FROM address_hints", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|err| format!("cache schema is unusable: {err}"))?;
        }

        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    fn remove_files(path: &Path) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(name));
        }
    }

    /// Path of the underlying file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Records an address hint, keeping at most `max_per_peer` newest entries.
    pub fn record_hint(
        &self,
        network_id: NetworkId,
        endpoint_id: &[u8; 32],
        addr: &str,
        max_per_peer: usize,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO address_hints (network_id, endpoint_id, addr, last_seen)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(network_id, endpoint_id, addr)
                 DO UPDATE SET last_seen = excluded.last_seen",
                params![
                    network_id.as_bytes().as_slice(),
                    endpoint_id.as_slice(),
                    addr,
                    super::state::now_unix()
                ],
            )
            .map_err(|err| Error::Storage(format!("cannot record address hint: {err}")))?;

        self.conn
            .execute(
                "DELETE FROM address_hints
                 WHERE network_id = ?1 AND endpoint_id = ?2 AND addr NOT IN (
                     SELECT addr FROM address_hints
                     WHERE network_id = ?1 AND endpoint_id = ?2
                     ORDER BY last_seen DESC LIMIT ?3
                 )",
                params![
                    network_id.as_bytes().as_slice(),
                    endpoint_id.as_slice(),
                    max_per_peer as i64
                ],
            )
            .map_err(|err| Error::Storage(format!("cannot prune address hints: {err}")))?;
        Ok(())
    }

    /// Returns every hint known for a network.
    pub fn hints_for_network(&self, network_id: NetworkId) -> Result<Vec<AddressHint>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT endpoint_id, addr, last_seen FROM address_hints
                 WHERE network_id = ?1 ORDER BY last_seen DESC",
            )
            .map_err(|err| Error::Storage(format!("cannot read address hints: {err}")))?;
        let rows = stmt
            .query_map(params![network_id.as_bytes().as_slice()], |row| {
                let endpoint_id: Vec<u8> = row.get(0)?;
                let addr: String = row.get(1)?;
                let last_seen: i64 = row.get(2)?;
                Ok((endpoint_id, addr, last_seen))
            })
            .map_err(|err| Error::Storage(format!("cannot read address hints: {err}")))?;

        let mut out = Vec::new();
        for row in rows {
            let (endpoint_id, addr, last_seen) =
                row.map_err(|err| Error::Storage(format!("cannot read hint row: {err}")))?;
            // A malformed row in a disposable store is skipped, not fatal.
            let Ok(endpoint_id) = <[u8; 32]>::try_from(endpoint_id.as_slice()) else {
                continue;
            };
            out.push(AddressHint {
                network_id,
                endpoint_id,
                addr,
                last_seen,
            });
        }
        Ok(out)
    }

    /// Drops all hints for a network.
    pub fn forget_network(&self, network_id: NetworkId) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM address_hints WHERE network_id = ?1",
                params![network_id.as_bytes().as_slice()],
            )
            .map_err(|err| Error::Storage(format!("cannot clear address hints: {err}")))?;
        Ok(())
    }
}
