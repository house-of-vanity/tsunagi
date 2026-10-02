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
use crate::state::{RecordBody, SignedRecord};

/// Schema version written by this build.
pub const SCHEMA_VERSION: i64 = 5;

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
    /// Local broadcast participation, enabled unless explicitly disabled.
    pub broadcast: bool,
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
        // The database file is created on demand, so the directory holding
        // it has to be too — with the same restricted permissions the agent
        // would have given it, never looser.
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            super::create_dir(parent)?;
        }
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

        // Migration 2 -> 3: the record body gained a hostname, which changed
        // the signing domain, and the version counter gained an author.
        //
        // The stored records are discarded rather than carried over. They
        // were signed under a domain that no longer verifies, so keeping them
        // would mean holding rows that every read has to reject — and one of
        // those rejections could be mistaken for corruption. Each member
        // re-publishes its claim on the next run, which is the one thing here
        // that repairs itself.
        if (2..3).contains(&found) {
            self.conn
                .execute_batch(
                    "BEGIN;
                     DROP TABLE IF EXISTS signed_records;
                     DROP TABLE IF EXISTS own_record_version;
                     COMMIT;",
                )
                .map_err(|err| self.corrupt(format!("cannot migrate schema to 3: {err}")))?;
            self.conn
                .execute_batch(SIGNED_RECORDS_SCHEMA)
                .map_err(|err| self.corrupt(format!("cannot migrate schema to 3: {err}")))?;
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
        if found < 4 {
            self.conn.execute_batch("BEGIN;
                ALTER TABLE networks ADD COLUMN broadcast INTEGER NOT NULL DEFAULT 1 CHECK (broadcast IN (0,1));
                PRAGMA user_version = 4;
                COMMIT;").map_err(|err| self.corrupt(format!("cannot migrate schema to 4: {err}")))?;
        }
        if found < 5 {
            self.conn
                .execute_batch(
                    "BEGIN;
                     CREATE TABLE IF NOT EXISTS peer_hostnames (
                         network_id  BLOB NOT NULL,
                         endpoint_id BLOB NOT NULL,
                         hostname    TEXT NOT NULL,
                         PRIMARY KEY (network_id, endpoint_id)
                     );
                     PRAGMA user_version = 5;
                     COMMIT;",
                )
                .map_err(|err| self.corrupt(format!("cannot migrate schema to 5: {err}")))?;
        }
        Ok(())
    }

    /// Confirms the expected tables exist, so that a truncated or foreign
    /// database is reported rather than used.
    fn verify_shape(&self) -> Result<()> {
        for table in [
            "device_identity",
            "networks",
            "settings",
            "signed_records",
            "peer_hostnames",
        ] {
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

    /// Replaces the device identity, giving up what the outgoing key held.
    ///
    /// A device key is the author of every record this agent has signed, so
    /// replacing it makes this a different member. The addresses and names
    /// the old key claimed would otherwise stay reserved to a key nobody
    /// holds, and nothing could ever free them — there is no way to sign on
    /// another author's behalf, and by design there is no authority that
    /// could overrule one.
    ///
    /// So the outgoing key signs a release for every network on its way out.
    /// That is the revocation: a positive statement, merged like any other,
    /// which frees the address and the name for whoever wants them next.
    ///
    /// All of it commits together. A crash part way through must not leave an
    /// identity that has already been replaced beside releases that were
    /// never written, because the old key would then be gone and unable to
    /// sign them.
    ///
    /// Returns the new identity and the networks a release was signed for.
    pub fn rotate_device_identity(&self) -> Result<(DeviceIdentity, Vec<NetworkId>)> {
        let outgoing = self.device_identity()?;
        let networks = self.list_networks()?;
        let replacement = DeviceIdentity::generate();

        let transaction = self
            .conn
            .unchecked_transaction()
            .map_err(|err| Error::Storage(format!("cannot begin a transaction: {err}")))?;

        let mut released = Vec::new();
        if let Some(outgoing) = &outgoing {
            let author = outgoing.endpoint_id();
            let signing = outgoing.signing_key();
            for network in &networks {
                let previous: Option<i64> = transaction
                    .query_row(
                        "SELECT version FROM own_record_version
                         WHERE network_id = ?1 AND author = ?2",
                        params![
                            network.network_id.as_bytes().as_slice(),
                            author.as_bytes().as_slice()
                        ],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|err| Error::Storage(format!("cannot read our version: {err}")))?;
                // A key that never published anything has nothing to give up.
                let Some(previous) = previous else { continue };

                let version = (previous.max(0) as u64).saturating_add(1);
                let record =
                    SignedRecord::sign(&signing, network.network_id, version, RecordBody::Release);
                let body = postcard::to_stdvec(&record.body)
                    .map_err(|err| Error::Storage(format!("cannot encode a record body: {err}")))?;
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
                    .map_err(|err| Error::Storage(format!("cannot store a release: {err}")))?;
                transaction
                    .execute(
                        "INSERT INTO own_record_version (network_id, author, version)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(network_id, author) DO UPDATE SET
                             version = max(version, excluded.version)",
                        params![
                            record.network.as_slice(),
                            record.author.as_slice(),
                            record.version as i64
                        ],
                    )
                    .map_err(|err| Error::Storage(format!("cannot store our version: {err}")))?;
                released.push(network.network_id);
            }
        }

        transaction
            .execute(
                "INSERT INTO device_identity (id, secret_key, created_at) VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET
                     secret_key = excluded.secret_key,
                     created_at = excluded.created_at",
                params![replacement.secret_bytes().as_slice(), now_unix()],
            )
            .map_err(|err| Error::Storage(format!("cannot store the new identity: {err}")))?;

        transaction
            .commit()
            .map_err(|err| Error::Storage(format!("cannot commit the new identity: {err}")))?;
        Ok((replacement, released))
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

    /// Saves local participation without changing identity, membership or auto-start.
    pub fn set_broadcast(&self, network_id: NetworkId, enabled: bool) -> Result<()> {
        let changed = self
            .conn
            .execute(
                "UPDATE networks SET broadcast = ?2 WHERE network_id = ?1",
                params![network_id.as_bytes().as_slice(), enabled as i64],
            )
            .map_err(|err| Error::Storage(format!("cannot update broadcast policy: {err}")))?;
        if changed == 0 {
            return Err(Error::NetworkUnknown(network_id));
        }
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
            .prepare("SELECT network_id, name, secret, auto_start, broadcast FROM networks ORDER BY name")
            .map_err(|err| Error::Storage(format!("cannot list networks: {err}")))?;
        let rows = stmt
            .query_map([], |row| {
                let id: Vec<u8> = row.get(0)?;
                let name: String = row.get(1)?;
                let secret: Vec<u8> = row.get(2)?;
                let auto_start: i64 = row.get(3)?;
                Ok((id, name, secret, auto_start != 0, row.get::<_, bool>(4)?))
            })
            .map_err(|err| Error::Storage(format!("cannot list networks: {err}")))?;

        let mut out = Vec::new();
        for row in rows {
            let (id, name, secret, auto_start, broadcast) =
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
                broadcast,
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
                "INSERT INTO own_record_version (network_id, author, version)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(network_id, author) DO UPDATE SET
                     version = max(version, excluded.version)",
                params![
                    record.network.as_slice(),
                    record.author.as_slice(),
                    record.version as i64
                ],
            )
            .map_err(|err| Error::Storage(format!("cannot store our version: {err}")))?;

        transaction
            .commit()
            .map_err(|err| Error::Storage(format!("cannot commit our record: {err}")))
    }

    /// The highest version an author has ever published for a network.
    ///
    /// Monotonic even if the record is later replaced by a conflicting one,
    /// so a number is never reused. Keyed by author as well: a replaced
    /// device key is a different author and starts its own sequence, while
    /// the outgoing one keeps its place so the release it signs on the way
    /// out cannot collide with something it already published.
    pub fn own_record_version(
        &self,
        network_id: NetworkId,
        author: iroh::EndpointId,
    ) -> Result<u64> {
        let version: Option<i64> = self
            .conn
            .query_row(
                "SELECT version FROM own_record_version WHERE network_id = ?1 AND author = ?2",
                params![
                    network_id.as_bytes().as_slice(),
                    author.as_bytes().as_slice()
                ],
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

    /// Remembers the hostname a member last announced.
    pub fn remember_peer_hostname(
        &self,
        network_id: NetworkId,
        endpoint_id: &[u8; 32],
        hostname: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO peer_hostnames (network_id, endpoint_id, hostname)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(network_id, endpoint_id) DO UPDATE SET hostname = excluded.hostname",
                params![
                    network_id.as_bytes().as_slice(),
                    endpoint_id.as_slice(),
                    hostname
                ],
            )
            .map_err(|err| Error::Storage(format!("cannot remember a hostname: {err}")))?;
        Ok(())
    }

    /// The last hostname every member of a network announced.
    pub fn peer_hostnames(&self, network_id: NetworkId) -> Result<Vec<([u8; 32], String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT endpoint_id, hostname FROM peer_hostnames WHERE network_id = ?1")
            .map_err(|err| Error::Storage(format!("cannot read hostnames: {err}")))?;
        let rows = stmt
            .query_map(params![network_id.as_bytes().as_slice()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|err| Error::Storage(format!("cannot read hostnames: {err}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, hostname) =
                row.map_err(|err| Error::Storage(format!("cannot read hostnames: {err}")))?;
            if let Ok(id) = <[u8; 32]>::try_from(id.as_slice()) {
                out.push((id, hostname));
            }
        }
        Ok(out)
    }

    /// Forgets every remembered hostname of a network.
    pub fn forget_peer_hostnames(&self, network_id: NetworkId) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM peer_hostnames WHERE network_id = ?1",
                params![network_id.as_bytes().as_slice()],
            )
            .map_err(|err| Error::Storage(format!("cannot forget hostnames: {err}")))?;
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
///
/// The version counter is keyed by author as well as network. A device key
/// can be replaced, and the replacement is a different author: it must start
/// its own sequence rather than inherit one, and the outgoing author's last
/// version has to survive so its release record cannot collide with
/// something it already published.
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
         network_id BLOB NOT NULL,
         author     BLOB NOT NULL,
         version    INTEGER NOT NULL,
         PRIMARY KEY (network_id, author)
     );
     PRAGMA user_version = 3;
     COMMIT;";

/// Seconds since the Unix epoch, saturating at 0 before it.
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
#[cfg(test)]
mod broadcast_storage_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::identity::NetworkKeys;

    #[test]
    fn a_remembered_hostname_survives_a_restart_and_follows_the_latest_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let name = NetworkName::new("hostnames").unwrap();
        let secret = NetworkSecret::from_bytes([9; 32]).unwrap();
        let id = NetworkKeys::derive(&name, &secret).network_id();
        let peer = [3u8; 32];

        let store = StateStore::open(&path).unwrap();
        store.remember_peer_hostname(id, &peer, "laptop").unwrap();
        store.remember_peer_hostname(id, &peer, "laptop-2").unwrap();
        drop(store);

        let store = StateStore::open(&path).unwrap();
        assert_eq!(
            store.peer_hostnames(id).unwrap(),
            vec![(peer, "laptop-2".to_string())]
        );
        store.forget_peer_hostnames(id).unwrap();
        assert!(store.peer_hostnames(id).unwrap().is_empty());
    }

    #[test]
    fn v3_migration_preserves_identity_and_networks_and_defaults_broadcast_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let name = NetworkName::new("migration-broadcast").unwrap();
        let secret = NetworkSecret::from_bytes([7; 32]).unwrap();
        let id = NetworkKeys::derive(&name, &secret).network_id();
        let store = StateStore::open(&path).unwrap();
        let identity = store
            .load_or_create_device_identity()
            .unwrap()
            .endpoint_id();
        store.upsert_network(id, &name, &secret, false).unwrap();
        store.set_hostname("old-host").unwrap();
        store
            .conn
            .execute_batch("ALTER TABLE networks DROP COLUMN broadcast; PRAGMA user_version=3;")
            .unwrap();
        drop(store);
        let store = StateStore::open(&path).unwrap();
        let networks = store.list_networks().unwrap();
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].network_id, id);
        assert!(!networks[0].auto_start);
        assert!(networks[0].broadcast);
        assert_eq!(store.hostname().unwrap().as_deref(), Some("old-host"));
        assert_eq!(
            store
                .load_or_create_device_identity()
                .unwrap()
                .endpoint_id(),
            identity
        );
        store.set_broadcast(id, false).unwrap();
        store.upsert_network(id, &name, &secret, true).unwrap();
        drop(store);
        let store = StateStore::open(&path).unwrap();
        assert!(
            !store.list_networks().unwrap()[0].broadcast,
            "rejoin and restart preserve opt-out"
        );
        store.remove_network(id).unwrap();
        store.upsert_network(id, &name, &secret, true).unwrap();
        assert!(
            store.list_networks().unwrap()[0].broadcast,
            "forgotten network gets defaults"
        );
    }
}
