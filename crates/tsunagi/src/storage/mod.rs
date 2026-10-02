//! Persistence, split into mandatory state and a disposable cache.
//!
//! | store          | contents                                               | on damage |
//! |----------------|--------------------------------------------------------|-----------|
//! | `state.sqlite` | device identity, network configuration, hostname        | hard error |
//! | `cache.sqlite` | address hints and other recoverable data                | discarded and recreated |
//!
//! Both files are created with owner-only permissions where the platform
//! supports it. The state directory additionally carries an ownership lock, see
//! [`DirectoryLock`].
//!
//! SQLite is synchronous. Every call that touches a database therefore runs on
//! a blocking pool via [`tokio::task::spawn_blocking`], and no database lock is
//! ever held across a network `await`.

mod cache;
mod lock;
mod state;

pub use cache::{AddressHint, CacheOutcome, CacheStore};
pub use lock::DirectoryLock;
pub use state::{SCHEMA_VERSION, StateStore, StoredNetwork};

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::config::StoragePaths;
use crate::error::{Error, Result};
use crate::identity::{DeviceIdentity, NetworkId, NetworkName, NetworkSecret};
use crate::state::SignedRecord;

/// Applies the pragmas both stores share.
fn apply_common_pragmas(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

/// Restricts a file to the current user where the platform supports it.
#[cfg(unix)]
fn restrict_permissions(file: &std::fs::File, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    file.set_permissions(perms).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// On Windows, files inherit the parent directory's ACL, which for the
/// per-user application data directory is already restricted to that user.
#[cfg(not(unix))]
fn restrict_permissions(_file: &std::fs::File, _path: &Path) -> Result<()> {
    Ok(())
}

/// Restricts a file to the user that owns it.
///
/// Part of what the system level offers a protocol: a plugin keeping keys of
/// its own on disk has the same obligation as the agent, and should not have
/// to work out the platform details again to meet it.
#[cfg(unix)]
pub fn restrict_path_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        Error::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Restricts a file to the user that owns it. A no-op off Unix.
#[cfg(not(unix))]
pub fn restrict_path_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Restricts a directory to the user that owns it.
#[cfg(unix)]
pub fn restrict_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|source| {
        Error::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Restricts a directory to the user that owns it. A no-op off Unix.
#[cfg(not(unix))]
pub fn restrict_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Creates a directory and every parent, restricted to this user.
pub fn create_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    restrict_dir_permissions(path)
}

/// Async facade over both stores, holding the directory ownership lock.
///
/// Cloning shares the same underlying connections and the same lock.
#[derive(Debug, Clone)]
pub struct Storage {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<StateStore>,
    cache: Mutex<Option<CacheStore>>,
    cache_outcome: CacheOutcome,
    paths: StoragePaths,
    lock: Mutex<Option<DirectoryLock>>,
}

impl Storage {
    /// Opens both stores and takes the ownership lock on the state directory.
    ///
    /// Fails with [`Error::StateLocked`] if another live agent owns the state
    /// directory, and with [`Error::StateCorrupted`] if the mandatory state is
    /// unusable. A broken cache is silently discarded and reported through
    /// [`Storage::cache_outcome`].
    pub fn open(paths: &StoragePaths) -> Result<Self> {
        create_dir(&paths.state_dir)?;
        create_dir(&paths.cache_dir)?;

        let lock = DirectoryLock::acquire(paths.lock_file())?;
        let state = StateStore::open(paths.state_db())?;
        let (cache, cache_outcome) = CacheStore::open_or_reset(paths.cache_db())?;

        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(state),
                cache: Mutex::new(Some(cache)),
                cache_outcome,
                paths: paths.clone(),
                lock: Mutex::new(Some(lock)),
            }),
        })
    }

    /// What happened to the cache when the agent started.
    pub fn cache_outcome(&self) -> &CacheOutcome {
        &self.inner.cache_outcome
    }

    /// The configured paths.
    pub fn paths(&self) -> &StoragePaths {
        &self.inner.paths
    }

    fn lock_state(&self) -> MutexGuard<'_, StateStore> {
        match self.inner.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn lock_cache(&self) -> MutexGuard<'_, Option<CacheStore>> {
        match self.inner.cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Runs a closure against the mandatory state store on the blocking pool.
    async fn with_state<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&StateStore) -> Result<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            let guard = match inner.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            f(&guard)
        })
        .await
        .map_err(|err| Error::Storage(format!("state task failed: {err}")))?
    }

    /// Runs a closure against the cache, tolerating an unavailable cache.
    ///
    /// If the cache has been disabled because it misbehaved, the closure is
    /// skipped and `default` is returned.
    async fn with_cache<T, F>(&self, default: T, f: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&CacheStore) -> Result<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        let joined = tokio::task::spawn_blocking(move || {
            let guard = match inner.cache.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            match guard.as_ref() {
                Some(cache) => f(cache),
                None => Err(Error::Storage("cache is unavailable".into())),
            }
        })
        .await;

        match joined {
            Ok(Ok(value)) => value,
            Ok(Err(err)) => {
                tracing::debug!(%err, "cache operation failed; continuing without it");
                default
            }
            Err(err) => {
                tracing::debug!(%err, "cache task failed; continuing without it");
                default
            }
        }
    }

    /// Loads or creates the persistent device identity.
    pub async fn device_identity(&self) -> Result<DeviceIdentity> {
        self.with_state(|state| state.load_or_create_device_identity())
            .await
    }

    /// Lists configured networks.
    pub async fn list_networks(&self) -> Result<Vec<StoredNetwork>> {
        self.with_state(|state| state.list_networks()).await
    }

    /// Stores or updates a network configuration.
    pub async fn upsert_network(
        &self,
        network_id: NetworkId,
        name: NetworkName,
        secret: NetworkSecret,
        auto_start: bool,
    ) -> Result<()> {
        self.with_state(move |state| state.upsert_network(network_id, &name, &secret, auto_start))
            .await
    }

    /// Persists local broadcast participation for one configured network.
    pub async fn set_broadcast(&self, network_id: NetworkId, enabled: bool) -> Result<()> {
        self.with_state(move |state| state.set_broadcast(network_id, enabled))
            .await
    }

    /// Updates the auto-start flag of a network.
    pub async fn set_auto_start(&self, network_id: NetworkId, auto_start: bool) -> Result<()> {
        self.with_state(move |state| state.set_auto_start(network_id, auto_start))
            .await
    }

    /// Removes a network configuration and its cached hints.
    pub async fn remove_network(&self, network_id: NetworkId) -> Result<()> {
        self.with_state(move |state| {
            state.remove_network(network_id)?;
            state.forget_signed_records(network_id)?;
            state.forget_peer_hostnames(network_id)
        })
        .await?;
        self.with_cache((), move |cache| cache.forget_network(network_id))
            .await;
        Ok(())
    }

    /// Reads the stored hostname.
    pub async fn hostname(&self) -> Result<Option<String>> {
        self.with_state(|state| state.hostname()).await
    }

    /// Writes the stored hostname.
    pub async fn set_hostname(&self, hostname: String) -> Result<()> {
        self.with_state(move |state| state.set_hostname(&hostname))
            .await
    }

    /// Remembers the hostname a member announced, so it can still be named
    /// once it is away.
    pub async fn remember_peer_hostname(
        &self,
        network_id: NetworkId,
        endpoint_id: [u8; 32],
        hostname: String,
    ) -> Result<()> {
        self.with_state(move |state| {
            state.remember_peer_hostname(network_id, &endpoint_id, &hostname)
        })
        .await
    }

    /// The hostnames members of a network last announced.
    pub async fn peer_hostnames(&self, network_id: NetworkId) -> Result<Vec<([u8; 32], String)>> {
        self.with_state(move |state| state.peer_hostnames(network_id))
            .await
    }

    /// Records an address hint. Failures are non-fatal.
    pub async fn record_hint(
        &self,
        network_id: NetworkId,
        endpoint_id: [u8; 32],
        addr: String,
        max_per_peer: usize,
    ) {
        self.with_cache((), move |cache| {
            cache.record_hint(network_id, &endpoint_id, &addr, max_per_peer)
        })
        .await;
    }

    /// Loads every signed record known for a network.
    pub async fn signed_records(&self, network_id: NetworkId) -> Result<Vec<SignedRecord>> {
        self.with_state(move |state| state.signed_records(network_id))
            .await
    }

    /// Stores a record received from another replica.
    pub async fn put_signed_record(&self, record: SignedRecord) -> Result<()> {
        self.with_state(move |state| state.put_signed_record(&record))
            .await
    }

    /// Stores one of this agent's own records and bumps its counter in one
    /// transaction, which must happen before the record is announced.
    pub async fn publish_own_record(&self, record: SignedRecord) -> Result<()> {
        self.with_state(move |state| state.publish_own_record(&record))
            .await
    }

    /// The highest version this agent has ever published for a network.
    pub async fn own_record_version(
        &self,
        network_id: NetworkId,
        author: iroh::EndpointId,
    ) -> Result<u64> {
        self.with_state(move |state| state.own_record_version(network_id, author))
            .await
    }

    /// Reads cached address hints. Returns an empty list if the cache is gone.
    pub async fn hints_for_network(&self, network_id: NetworkId) -> Vec<AddressHint> {
        self.with_cache(Vec::new(), move |cache| cache.hints_for_network(network_id))
            .await
    }

    /// Synchronously reads the hostname. Used only during startup.
    pub(crate) fn hostname_blocking(&self) -> Result<Option<String>> {
        self.lock_state().hostname()
    }

    /// Whether the cache is currently usable.
    pub fn cache_healthy(&self) -> bool {
        self.lock_cache().is_some()
    }

    /// Releases the state directory ownership lock.
    ///
    /// Called by [`crate::Agent::shutdown`] so that a cleanly stopped agent
    /// leaves its directory immediately claimable by another instance. The
    /// databases stay open and readable, but this handle no longer owns the
    /// directory and must not be used to write after this point.
    pub fn release_ownership_lock(&self) {
        let mut guard = match self.inner.lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.take();
    }
}

/// What a wipe covers: every entry in the two directories.
///
/// Reported before anything is removed, and again afterwards, because a
/// command whose whole job is to destroy state has to be able to say exactly
/// what it is about to destroy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WipePlan {
    /// Entries in the state directory, which is the mandatory state and
    /// anything a plugin keeps beside it.
    pub state: Vec<std::path::PathBuf>,
    /// Entries in the cache directory.
    pub cache: Vec<std::path::PathBuf>,
}

impl WipePlan {
    /// Whether there is anything to remove at all.
    pub fn is_empty(&self) -> bool {
        self.state.is_empty() && self.cache.is_empty()
    }

    /// Every entry, state first.
    pub fn entries(&self) -> impl Iterator<Item = &std::path::Path> {
        self.state
            .iter()
            .chain(self.cache.iter())
            .map(std::path::PathBuf::as_path)
    }
}

/// Lists what [`wipe`] would remove, without removing anything.
pub fn wipe_plan(paths: &StoragePaths) -> Result<WipePlan> {
    Ok(WipePlan {
        state: removable(&paths.state_dir, &paths.state_db())?,
        cache: removable(&paths.cache_dir, &paths.cache_db())?,
    })
}

/// Removes everything in both directories, leaving this device a stranger.
///
/// The device identity, every network it belongs to, every signed record and
/// everything a plugin kept beside them. The next start generates a new
/// identity and knows nothing, which is the point: after this there is no
/// membership left to be surprised by.
///
/// What it is **not** is a goodbye. Other members keep the claims this device
/// signed, because signed state has no expiry and there is nobody left here
/// to sign a release. Leaving each network first with
/// [`crate::Agent::leave_network`] is what frees the address and the name.
///
/// Refuses while an agent owns the state directory, and refuses a directory
/// with no `state.sqlite` in it — a wipe pointed at the wrong place by a
/// mistyped `--state-dir` would otherwise remove somebody's documents.
pub fn wipe(paths: &StoragePaths) -> Result<WipePlan> {
    let plan = wipe_plan(paths)?;
    // Held across the removal, so an agent cannot start into a directory
    // that is half gone. The lock file is itself removed at the end: on
    // Unix the lock lives on the open handle, not on the name.
    let lock = DirectoryLock::acquire(paths.lock_file())?;

    for entry in plan.entries() {
        remove_entry(entry)?;
    }
    drop(lock);
    // Created by acquiring the lock a moment ago, so it is ours to remove
    // and nothing is left behind claiming the directory.
    let _ = std::fs::remove_file(paths.lock_file());
    Ok(plan)
}

/// Every entry of `dir`, once `marker` proves it is one of ours.
///
/// An empty or missing directory is nothing to remove rather than an error:
/// wiping twice must be as ordinary as wiping once.
fn removable(dir: &Path, marker: &Path) -> Result<Vec<std::path::PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    let read = std::fs::read_dir(dir).map_err(|source| Error::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in read {
        let entry = entry.map_err(|source| Error::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        entries.push(entry.path());
    }
    if entries.is_empty() {
        return Ok(entries);
    }

    // The marker is what tells a state directory from a directory that
    // merely got named as one. The lock file counts too: an agent that
    // crashed before writing anything still leaves that.
    let ours = marker.exists() || dir.join("state.lock").exists();
    if !ours {
        return Err(Error::Storage(format!(
            "{} does not look like a tsunagi directory: no {} in it. Nothing was removed.",
            dir.display(),
            marker.file_name().map_or_else(
                || marker.display().to_string(),
                |name| name.to_string_lossy().into_owned()
            )
        )));
    }
    entries.sort();
    Ok(entries)
}

fn remove_entry(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        // Gone between the plan and the removal is the outcome asked for.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let removed = if metadata.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    removed.map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}
