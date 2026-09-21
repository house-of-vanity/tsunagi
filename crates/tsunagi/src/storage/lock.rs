//! Ownership lock for a state directory.
//!
//! One persistent state directory belongs to exactly one live agent instance.
//! Checking whether a file exists is not enough — a stale file from a crashed
//! process must not block a restart, and two concurrently starting agents must
//! not both win. An advisory OS file lock gives both properties.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use fs4::{FileExt, TryLockError};

use crate::error::{Error, Result};

/// An exclusive lock held for the lifetime of an agent.
///
/// Dropping it releases the lock, so a cleanly stopped agent leaves the
/// directory immediately reopenable.
#[derive(Debug)]
pub struct DirectoryLock {
    file: File,
    path: PathBuf,
}

impl DirectoryLock {
    /// Acquires the lock, failing fast if another live agent holds it.
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })?;
        super::restrict_permissions(&file, &path)?;

        match FileExt::try_lock(&file) {
            Ok(()) => Ok(Self { file, path }),
            Err(TryLockError::WouldBlock) => Err(Error::StateLocked {
                path: path
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| path.clone()),
            }),
            Err(TryLockError::Error(source)) => Err(Error::Io { path, source }),
        }
    }

    /// The path of the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DirectoryLock {
    fn drop(&mut self) {
        // Best effort: the OS releases the lock when the descriptor closes anyway.
        let _ = FileExt::unlock(&self.file);
    }
}
