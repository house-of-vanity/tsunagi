//! The plugin's own key store.
//!
//! Deliberately a separate SQLite file from the agent's `state.sqlite`: plugin
//! keys are not the iroh identity and not the network secret, and their
//! lifecycle is the plugin's business alone.
//!
//! One key per network, so a participant presents a different WireGuard
//! identity in each network it belongs to.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};

use tsunagi::dataplane::PluginError;
use tsunagi::identity::NetworkId;

use crate::keys::{KEY_LEN, WgSecretKey};

/// Schema version written by this build.
pub const SCHEMA_VERSION: i64 = 1;

/// Per-network WireGuard private keys.
#[derive(Debug)]
pub struct WgKeyStore {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl WgKeyStore {
    /// Opens, creating the file and its directory if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PluginError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            tsunagi::storage::create_dir(parent)
                .map_err(|err| PluginError::Other(format!("cannot create {parent:?}: {err}")))?;
        }
        let existed = path.exists();
        let conn = Connection::open(&path).map_err(|err| {
            PluginError::Other(format!("cannot open the WireGuard key store: {err}"))
        })?;
        tsunagi::storage::restrict_path_permissions(&path)
            .map_err(|err| PluginError::Other(format!("cannot secure the key store: {err}")))?;

        conn.busy_timeout(std::time::Duration::from_secs(5))
            .and_then(|()| conn.pragma_update(None, "journal_mode", "WAL"))
            .and_then(|()| conn.pragma_update(None, "synchronous", "NORMAL"))
            .map_err(|err| PluginError::Other(format!("cannot configure the key store: {err}")))?;

        if existed {
            let integrity: String = conn
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))
                .map_err(|err| {
                    PluginError::Other(format!("WireGuard key store is unusable: {err}"))
                })?;
            if integrity != "ok" {
                return Err(PluginError::Other(format!(
                    "WireGuard key store at {} is corrupt and will not be recreated: {integrity}",
                    path.display()
                )));
            }
        }

        let found: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|err| PluginError::Other(format!("cannot read the schema version: {err}")))?;
        if found > SCHEMA_VERSION {
            return Err(PluginError::Other(format!(
                "WireGuard key store schema {found} is newer than {SCHEMA_VERSION}"
            )));
        }
        if found < SCHEMA_VERSION {
            conn.execute_batch(
                "BEGIN;
                 CREATE TABLE IF NOT EXISTS network_keys (
                     network_id BLOB PRIMARY KEY,
                     secret     BLOB NOT NULL,
                     created_at INTEGER NOT NULL
                 );
                 PRAGMA user_version = 1;
                 COMMIT;",
            )
            .map_err(|err| PluginError::Other(format!("cannot create the schema: {err}")))?;
        }

        Ok(Self {
            conn: Mutex::new(conn),
            path,
        })
    }

    /// Path of the underlying file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads the stored key for `network`, or generates, stores and returns a fresh one.
    pub fn load_or_create(&self, network: NetworkId) -> Result<WgSecretKey, PluginError> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| PluginError::Other("key store lock is poisoned".into()))?;

        let existing: Option<Vec<u8>> = guard
            .query_row(
                "SELECT secret FROM network_keys WHERE network_id = ?1",
                params![network.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| PluginError::Other(format!("cannot read the key store: {err}")))?;

        if let Some(secret) = existing {
            let bytes = <[u8; KEY_LEN]>::try_from(secret.as_slice()).map_err(|_| {
                PluginError::Other(format!(
                    "stored WireGuard key for {} is {} bytes, expected {KEY_LEN}",
                    network.fmt_short(),
                    secret.len()
                ))
            })?;
            return Ok(WgSecretKey::from_bytes(&bytes));
        }

        let fresh = WgSecretKey::generate();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| PluginError::Other(format!("system clock is broken: {err}")))?
            .as_secs() as i64;

        guard
            .execute(
                "INSERT INTO network_keys (network_id, secret, created_at) VALUES (?1, ?2, ?3)",
                params![
                    network.as_bytes().as_slice(),
                    fresh.as_bytes().as_slice(),
                    now
                ],
            )
            .map_err(|err| PluginError::Other(format!("cannot write the key store: {err}")))?;

        Ok(fresh)
    }

    /// Removes the stored key for `network`.
    pub fn forget(&self, network: NetworkId) -> Result<(), PluginError> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| PluginError::Other("key store lock is poisoned".into()))?;
        guard
            .execute(
                "DELETE FROM network_keys WHERE network_id = ?1",
                params![network.as_bytes().as_slice()],
            )
            .map_err(|err| {
                PluginError::Other(format!("cannot delete from the key store: {err}"))
            })?;
        Ok(())
    }
}
