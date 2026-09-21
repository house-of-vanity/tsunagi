//! The mandatory state store, `state.sqlite`.
//!
//! Holds the persistent device identity, configured networks (including their
//! shared secrets, which are needed to re-derive keys after a restart), the
//! stored hostname and auto-start flags.
//!
//! Corruption is reported, never silently repaired: a damaged state store must
//! not quietly turn into a brand new identity.
//!
//! Future work will add per-author record versions, accepted signed states and
//! revocations here. When that lands, writing an event and bumping the author's
//! own counter must happen in one SQLite transaction *before* the change is
//! published to the network.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::{Error, Result};
use crate::identity::{DeviceIdentity, NetworkId, NetworkName, NetworkSecret};
use crate::state::SignedRecord;

/// Schema version written by this build.
pub const SCHEMA_VERSION: i64 = 2;

/// Key of the stored hostname setting.
const SETTING_HOSTNAME: &str = "hostname";

/// A network as persisted in the state store.
///
/// The secret is held in a [`NetworkSecret`], which redacts itself from `Debug`
/// and zeroizes on drop.
#[derive(Debug, Clone)]
pub struct StoredNetwork {
    /// Derived public network identifier.
    pub network_id: NetworkId,
    /// Network name.
    pub name: NetworkName,
    /// Shared secret, needed to re-derive keys after restart.
    pub secret: NetworkSecret,
    /// Whether the network is activated automatically at agent startup.
    pub auto_start: bool,
}

/// The mandatory state store.
#[derive(Debug)]
pub struct StateStore {
    conn: Connection,
    path: PathBuf,
}

impl StateStore {
    /// Opens (creating if absent) the state store at `path`.
    ///
    /// Returns [`Error::StateCorrupted`] if the file exists but is not a usable
    /// database. The file is never deleted or recreated by this function.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let existed = path.exists();
        let conn = Connection::open(&path).map_err(|err| Error::StateCorrupted {
            path: path.clone(),
            reason: format!("cannot open database: {err}"),
        })?;

        super::restrict_path_permissions(&path)?;
        super::apply_common_pragmas(&conn).map_err(|err| Error::StateCorrupted {
            path: path.clone(),
            reason: format!("cannot configure database: {err}"),
        })?;

        if existed {
            let integrity: String = conn
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))
                .map_err(|err| Error::StateCorrupted {
                    path: path.clone(),
                    reason: format!("integrity check failed: {err}"),
                })?;
            if integrity != "ok" {
                return Err(Error::StateCorrupted {
                    path,
                    reason: format!("integrity check reported: {integrity}"),
                });
            }
        }

        let store = Self { conn, path };
        store.migrate()?;
        Ok(store)
    }

    /// Path of the underlying file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn corrupt(&self, reason: impl std::fmt::Display) -> Error {
        Error::StateCorrupted {
            path: self.path.clone(),
            reason: reason.to_string(),
        }
    }

    fn migrate(&self) -> Result<()> {
        let found: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|err| self.corrupt(format!("cannot read schema version: {err}")))?;

        if found > SCHEMA_VERSION {
            return Err(Error::UnsupportedSchema {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found == SCHEMA_VERSION {
            return self.verify_shape();
        }

        // Migration 1 -> 2: signed records that outlive a session.
        if (1..2).contains(&found) {
            self.conn
                .execute_batch(SIGNED_RECORDS_SCHEMA)
                .map_err(|err| self.corrupt(format!("cannot migrate schema to 2: {err}")))?;
        }

        // Migration 0 -> 1: initial schema.
        if found < 1 {
            self.conn
                .execute_batch(
                    "BEGIN;
                     CREATE TABLE device_identity (
                         id          INTEGER PRIMARY KEY CHECK (id = 1),
                         secret_key  BLOB NOT NULL,
                         created_at  INTEGER NOT NULL
                     );
                     CREATE TABLE networks (
                         network_id  BLOB PRIMARY KEY,
                         name        TEXT NOT NULL,
                         secret      BLOB NOT NULL,
                         auto_start  INTEGER NOT NULL DEFAULT 1,
                         created_at  INTEGER NOT NULL
                     );
                     CREATE TABLE settings (
                         key    TEXT PRIMARY KEY,
                         value  TEXT NOT NULL
                     );
                     PRAGMA user_version = 1;
                     COMMIT;",
                )
                .map_err(|err| self.corrupt(format!("cannot create schema: {err}")))?;
            self.conn
                .execute_batch(SIGNED_RECORDS_SCHEMA)
                .map_err(|err| self.corrupt(format!("cannot create schema: {err}")))?;
        }
        Ok(())
    }

    /// Confirms the expected tables exist, so that a truncated or foreign
    /// database is reported rather than used.
    fn verify_shape(&self) -> Result<()> {
        for table in ["device_identity", "networks", "settings", "signed_records"] {
            let present: Option<String> = self
                .conn
                .query_row(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    params![table],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|err| self.corrupt(format!("cannot inspect schema: {err}")))?;
            if present.is_none() {
                return Err(self.corrupt(format!("table `{table}` is missing")));
            }
        }
        Ok(())
    }

    /// Loads the stored device identity, if there is one.
    ///
    /// Reads and never writes, so asking who this device is does not decide
    /// it. A store that has never run an agent has no identity yet, which is
    /// `None` rather than an error.
    ///
    /// A stored key of the wrong length is a corruption error, never a reason
    /// to silently mint a new identity.
    pub fn device_identity(&self) -> Result<Option<DeviceIdentity>> {
        let stored: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT secret_key FROM device_identity WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| self.corrupt(format!("cannot read device identity: {err}")))?;

        let Some(bytes) = stored else {
            return Ok(None);
        };
        let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            self.corrupt(format!(
                "stored device key has {} bytes, expected 32; refusing to replace it",
                bytes.len()
            ))
        })?;
        Ok(Some(DeviceIdentity::from_secret_bytes(&bytes)))
    }

    /// Loads the stored device identity, creating one on first use.
    pub fn load_or_create_device_identity(&self) -> Result<DeviceIdentity> {
        if let Some(identity) = self.device_identity()? {
            return Ok(identity);
        }

        let identity = DeviceIdentity::generate();
        self.conn
            .execute(
                "INSERT INTO device_identity (id, secret_key, created_at) VALUES (1, ?1, ?2)",
                params![identity.secret_bytes().as_slice(), now_unix()],
            )
            .map_err(|err| self.corrupt(format!("cannot store device identity: {err}")))?;
        Ok(identity)
    }

    /// Inserts or updates a network configuration.
    pub fn upsert_network(
        &self,
        network_id: NetworkId,
        name: &NetworkName,
        secret: &NetworkSecret,
        auto_start: bool,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO networks (network_id, name, secret, auto_start, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(network_id) DO UPDATE SET
                     name = excluded.name,
                     secret = excluded.secret,
                     auto_start = excluded.auto_start",
                params![
                    network_id.as_bytes().as_slice(),
                    name.as_str(),
                    secret.expose(),
                    auto_start as i64,
                    now_unix()
                ],
            )
            .map_err(|err| Error::Storage(format!("cannot store network: {err}")))?;
        Ok(())
    }

    /// Sets the auto-start flag of a configured network.
    pub fn set_auto_start(&self, network_id: NetworkId, auto_start: bool) -> Result<()> {
        self.conn
            .execute(
                "UPDATE networks SET auto_start = ?2 WHERE network_id = ?1",
                params![network_id.as_bytes().as_slice(), auto_start as i64],
            )
            .map_err(|err| Error::Storage(format!("cannot update network: {err}")))?;
        Ok(())
    }

    /// Removes a network configuration entirely.
    pub fn remove_network(&self, network_id: NetworkId) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM networks WHERE network_id = ?1",
                params![network_id.as_bytes().as_slice()],
            )
            .map_err(|err| Error::Storage(format!("cannot remove network: {err}")))?;
        Ok(())
    }

    /// Lists every configured network.
    pub fn list_networks(&self) -> Result<Vec<StoredNetwork>> {
        let mut stmt = self
            .conn
            .prepare("SELECT network_id, name, secret, auto_start FROM networks ORDER BY name")
            .map_err(|err| Error::Storage(format!("cannot list networks: {err}")))?;
        let rows = stmt
            .query_map([], |row| {
                let id: Vec<u8> = row.get(0)?;
                let name: String = row.get(1)?;
                let secret: Vec<u8> = row.get(2)?;
                let auto_start: i64 = row.get(3)?;
                Ok((id, name, secret, auto_start != 0))
            })
            .map_err(|err| Error::Storage(format!("cannot list networks: {err}")))?;

        let mut out = Vec::new();
        for row in rows {
            let (id, name, secret, auto_start) =
                row.map_err(|err| Error::Storage(format!("cannot read network row: {err}")))?;
            let id: [u8; 32] = id
                .as_slice()
                .try_into()
                .map_err(|_| self.corrupt("stored network id is not 32 bytes"))?;
            out.push(StoredNetwork {
                network_id: NetworkId::from_bytes(id),
                name: NetworkName::new(name)?,
                secret: NetworkSecret::from_bytes(secret)?,
                auto_start,
            });
        }
        Ok(out)
    }

    /// Reads the stored hostname, if any.
    pub fn hostname(&self) -> Result<Option<String>> {
        self.get_setting(SETTING_HOSTNAME)
    }

    /// Stores the hostname.
    ///
    /// Today this is a local setting. In the future a rename must be a signed
    /// record that revokes the specific old binding and announces the new one,
    /// ideally atomically in one record.
    pub fn set_hostname(&self, hostname: &str) -> Result<()> {
        self.set_setting(SETTING_HOSTNAME, hostname)
    }

    /// Loads every signed record known for a network.
    ///
    /// Records are returned as stored; the caller verifies them, because the
    /// database is not a trust boundary — a restored backup or a copied file
    /// could contain anything.
    pub fn signed_records(&self, network_id: NetworkId) -> Result<Vec<SignedRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT author, version, body, signature FROM signed_records
                 WHERE network_id = ?1",
            )
            .map_err(|err| Error::Storage(format!("cannot read signed records: {err}")))?;
        let rows = stmt
            .query_map(params![network_id.as_bytes().as_slice()], |row| {
                let author: Vec<u8> = row.get(0)?;
                let version: i64 = row.get(1)?;
                let body: Vec<u8> = row.get(2)?;
                let signature: Vec<u8> = row.get(3)?;
                Ok((author, version, body, signature))
            })
            .map_err(|err| Error::Storage(format!("cannot read signed records: {err}")))?;

        let mut out = Vec::new();
        for row in rows {
            let (author, version, body, signature) =
                row.map_err(|err| Error::Storage(format!("cannot read a record row: {err}")))?;
            let Ok(author) = <[u8; 32]>::try_from(author.as_slice()) else {
                continue;
            };
            let Ok(body) = postcard::from_bytes(&body) else {
                continue;
            };
            out.push(SignedRecord {
                author,
                network: *network_id.as_bytes(),
                version: version as u64,
                body,
                signature,
            });
        }
        Ok(out)
    }

    /// Stores a record received from somebody else.
    pub fn put_signed_record(&self, record: &SignedRecord) -> Result<()> {
        let body = postcard::to_stdvec(&record.body)
            .map_err(|err| Error::Storage(format!("cannot encode a record body: {err}")))?;
        self.conn
            .execute(
                "INSERT INTO signed_records (network_id, author, version, body, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(network_id, author) DO UPDATE SET
                     version = excluded.version,
                     body = excluded.body,
                     signature = excluded.signature",
                params![
                    record.network.as_slice(),
                    record.author.as_slice(),
                    record.version as i64,
                    body,
                    record.signature
                ],
            )
            .map_err(|err| Error::Storage(format!("cannot store a signed record: {err}")))?;
        Ok(())
    }

    /// Stores one of **our own** records and bumps our counter, atomically.
    ///
    /// The model requires that a record and the author's own version counter
    /// are committed together, and **before** the record is published, so a
    /// crash can never leave us able to reuse a version number we already put
    /// on the wire.
    pub fn publish_own_record(&self, record: &SignedRecord) -> Result<()> {
        let body = postcard::to_stdvec(&record.body)
            .map_err(|err| Error::Storage(format!("cannot encode a record body: {err}")))?;
        let transaction = self
            .conn
            .unchecked_transaction()
            .map_err(|err| Error::Storage(format!("cannot begin a transaction: {err}")))?;

        transaction
            .execute(
                "INSERT INTO signed_records (network_id, author, version, body, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(network_id, author) DO UPDATE SET
                     version = excluded.version,
                     body = excluded.body,
                     signature = excluded.signature",
                params![
                    record.network.as_slice(),
                    record.author.as_slice(),
                    record.version as i64,
                    body,
                    record.signature
                ],
            )
            .map_err(|err| Error::Storage(format!("cannot store our record: {err}")))?;
        transaction
            .execute(
                "INSERT INTO own_record_version (network_id, version) VALUES (?1, ?2)
                 ON CONFLICT(network_id) DO UPDATE SET
                     version = max(version, excluded.version)",
                params![record.network.as_slice(), record.version as i64],
            )
            .map_err(|err| Error::Storage(format!("cannot store our version: {err}")))?;

        transaction
            .commit()
            .map_err(|err| Error::Storage(format!("cannot commit our record: {err}")))
    }

    /// The highest version we have ever published for a network.
    ///
    /// Monotonic even if our record is later replaced by a conflicting one,
    /// so we never reuse a number.
    pub fn own_record_version(&self, network_id: NetworkId) -> Result<u64> {
        let version: Option<i64> = self
            .conn
            .query_row(
                "SELECT version FROM own_record_version WHERE network_id = ?1",
                params![network_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| Error::Storage(format!("cannot read our version: {err}")))?;
        Ok(version.unwrap_or(0).max(0) as u64)
    }

    /// Forgets every record of a network.
    pub fn forget_signed_records(&self, network_id: NetworkId) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM signed_records WHERE network_id = ?1",
                params![network_id.as_bytes().as_slice()],
            )
            .map_err(|err| Error::Storage(format!("cannot clear signed records: {err}")))?;
        Ok(())
    }

    /// Reads an arbitrary setting.
    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| Error::Storage(format!("cannot read setting `{key}`: {err}")))
    }

    /// Writes an arbitrary setting.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map_err(|err| Error::Storage(format!("cannot write setting `{key}`: {err}")))?;
        Ok(())
    }
}

/// Schema for the signed records described in [`crate::state`].
const SIGNED_RECORDS_SCHEMA: &str = "BEGIN;
     CREATE TABLE IF NOT EXISTS signed_records (
         network_id BLOB NOT NULL,
         author     BLOB NOT NULL,
         version    INTEGER NOT NULL,
         body       BLOB NOT NULL,
         signature  BLOB NOT NULL,
         PRIMARY KEY (network_id, author)
     );
     CREATE TABLE IF NOT EXISTS own_record_version (
         network_id BLOB PRIMARY KEY,
         version    INTEGER NOT NULL
     );
     PRAGMA user_version = 2;
     COMMIT;";

/// Seconds since the Unix epoch, saturating at 0 before it.
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
