//! The plugin's own key store.
//!
//! Deliberately a separate SQLite file from the agent's `state.sqlite`: plugin
//! keys are not the iroh identity and not the network secret, and their
//! lifecycle is the plugin's business alone.
//!
//! One key per network, so a participant presents a different WireGuard
//! identity — and therefore a different overlay address — in each network it
//! belongs to.
//!
//! A damaged key store is an error, never a silent regeneration: a new key
//! would silently move this agent to a different overlay address and orphan
//! every peer's configuration.

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

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Imports missing network keys from an older carrier-specific store, atomically.
    /// The source is read-only and existing canonical keys always win.
    pub fn import_legacy(&self, path: &Path) -> Result<(), PluginError> {
        if !path.exists() || path == self.path {
            return Ok(());
        }
        let fail = |err: rusqlite::Error| {
            PluginError::Other(format!("cannot import legacy data keys: {err}"))
        };
        let source = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(fail)?;
        let integrity: String = source
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(fail)?;
        let schema: i64 = source
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(fail)?;
        if integrity != "ok" || schema != SCHEMA_VERSION {
            return Err(PluginError::Other(
                "legacy data key store is damaged or has an unsupported schema".into(),
            ));
        }
        let mut statement = source.prepare("SELECT network_id, secret, created_at, length(network_id), length(secret) FROM network_keys").map_err(fail)?;
        let mut rows = statement.query([]).map_err(fail)?;
        let mut target = self.lock();
        let transaction = target.transaction().map_err(fail)?;
        while let Some(row) = rows.next().map_err(fail)? {
            let id_len: i64 = row.get(3).map_err(fail)?;
            let key_len: i64 = row.get(4).map_err(fail)?;
            if id_len != 32 || key_len != KEY_LEN as i64 {
                return Err(PluginError::Other(
                    "legacy data key has an invalid length".into(),
                ));
            }
            let id: Vec<u8> = row.get(0).map_err(fail)?;
            let key = zeroize::Zeroizing::new(row.get::<_, Vec<u8>>(1).map_err(fail)?);
            let created: i64 = row.get(2).map_err(fail)?;
            transaction.execute("INSERT OR IGNORE INTO network_keys(network_id, secret, created_at) VALUES (?1, ?2, ?3)", params![id, key.as_slice(), created]).map_err(fail)?;
        }
        transaction.commit().map_err(fail)?;
        Ok(())
    }

    /// Returns this agent's key for a network, creating it on first use.
    pub fn load_or_create(&self, network: NetworkId) -> Result<WgSecretKey, PluginError> {
        let conn = self.lock();
        let stored: Option<Vec<u8>> = conn
            .query_row(
                "SELECT secret FROM network_keys WHERE network_id = ?1",
                params![network.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| PluginError::Other(format!("cannot read the WireGuard key: {err}")))?;

        if let Some(bytes) = stored {
            let bytes = <[u8; KEY_LEN]>::try_from(bytes.as_slice()).map_err(|_| {
                PluginError::Other(format!(
                    "the stored WireGuard key for network {} is not {KEY_LEN} bytes; \
                     refusing to replace it",
                    network.fmt_short()
                ))
            })?;
            return Ok(WgSecretKey::from_bytes(&bytes));
        }

        let key = WgSecretKey::generate();
        conn.execute(
            "INSERT INTO network_keys (network_id, secret, created_at) VALUES (?1, ?2, ?3)",
            params![
                network.as_bytes().as_slice(),
                key.expose().as_slice(),
                now_unix()
            ],
        )
        .map_err(|err| PluginError::Other(format!("cannot store the WireGuard key: {err}")))?;
        Ok(key)
    }

    /// Deletes the key for a network.
    ///
    /// Not called when a network is merely deactivated: coming back should
    /// keep the same overlay address.
    pub fn forget(&self, network: NetworkId) -> Result<(), PluginError> {
        self.lock()
            .execute(
                "DELETE FROM network_keys WHERE network_id = ?1",
                params![network.as_bytes().as_slice()],
            )
            .map_err(|err| PluginError::Other(format!("cannot remove the WireGuard key: {err}")))?;
        Ok(())
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use tsunagi::identity::{NetworkKeys, NetworkName, NetworkSecret};

    fn network(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes(vec![8u8; 32]).unwrap(),
        )
        .network_id()
    }

    #[test]
    fn keys_are_per_network_and_survive_reopening() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wireguard.sqlite");
        let first = network("one");
        let second = network("two");

        let (key_one, key_two) = {
            let store = WgKeyStore::open(&path).unwrap();
            let a = store.load_or_create(first).unwrap();
            let b = store.load_or_create(second).unwrap();
            assert_ne!(a.public(), b.public(), "networks get separate identities");
            assert_eq!(a.public(), store.load_or_create(first).unwrap().public());
            (a.public(), b.public())
        };

        let reopened = WgKeyStore::open(&path).unwrap();
        assert_eq!(reopened.load_or_create(first).unwrap().public(), key_one);
        assert_eq!(reopened.load_or_create(second).unwrap().public(), key_two);

        reopened.forget(first).unwrap();
        assert_ne!(reopened.load_or_create(first).unwrap().public(), key_one);
    }

    #[test]
    fn a_corrupt_key_store_is_an_error_not_a_new_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("wireguard.sqlite");
        let original = {
            let store = WgKeyStore::open(&path).unwrap();
            store.load_or_create(network("keep")).unwrap().public()
        };

        std::fs::write(&path, [0x5a; 4096]).unwrap();
        let result = WgKeyStore::open(&path);
        assert!(
            result.is_err(),
            "a damaged key store must not silently mint a new identity (was {original})"
        );
    }

    #[tokio::test]
    async fn forgetting_an_imported_key_cannot_resurrect_it_on_restart() {
        use crate::{WireguardConfig, WireguardPlugin};
        use tsunagi::dataplane::IpPlugin;
        let dir = tempfile::TempDir::new().unwrap();
        let id = network("forgotten-import");
        let legacy_path = dir.path().join("old.sqlite");
        let original = WgKeyStore::open(&legacy_path)
            .unwrap()
            .load_or_create(id)
            .unwrap()
            .public();
        let mut config = WireguardConfig::new(dir.path().join("canonical"));
        config.legacy_key_stores.push(legacy_path);
        let plugin = WireguardPlugin::open(config.clone()).await.unwrap();
        plugin.on_network_forgotten(id).await;
        plugin.shutdown().await;
        let restarted = WireguardPlugin::open(config.clone()).await.unwrap();
        let key = WgKeyStore::open(config.key_store_path())
            .unwrap()
            .load_or_create(id)
            .unwrap()
            .public();
        assert_ne!(key, original);
        restarted.shutdown().await;
    }

    #[test]
    fn legacy_import_preserves_keys_and_never_overwrites_the_canonical_identity() {
        let dir = tempfile::TempDir::new().unwrap();
        let legacy = WgKeyStore::open(dir.path().join("legacy.sqlite")).unwrap();
        let canonical = WgKeyStore::open(dir.path().join("canonical.sqlite")).unwrap();
        let imported = network("imported");
        let existing = network("existing");
        let imported_key = legacy.load_or_create(imported).unwrap().public();
        legacy.load_or_create(existing).unwrap();
        let existing_key = canonical.load_or_create(existing).unwrap().public();
        canonical.import_legacy(legacy.path()).unwrap();
        canonical.import_legacy(legacy.path()).unwrap();
        assert_eq!(
            canonical.load_or_create(imported).unwrap().public(),
            imported_key
        );
        assert_eq!(
            canonical.load_or_create(existing).unwrap().public(),
            existing_key
        );
        assert_eq!(
            legacy.load_or_create(imported).unwrap().public(),
            imported_key
        );
    }

    #[test]
    fn a_damaged_legacy_store_aborts_import_without_regenerating_keys() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("legacy.sqlite");
        std::fs::write(&path, b"damaged SQLite").unwrap();
        let canonical = WgKeyStore::open(dir.path().join("canonical.sqlite")).unwrap();
        assert!(canonical.import_legacy(&path).is_err());
        canonical
            .import_legacy(&dir.path().join("absent.sqlite"))
            .unwrap();
        assert!(!dir.path().join("absent.sqlite").exists());
    }
}
