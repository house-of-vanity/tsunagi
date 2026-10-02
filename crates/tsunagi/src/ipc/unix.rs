//! A Unix socket adapter for the local control interface.
//!
//! One of the per-platform adapters; see [`super`]. It provides only what is
//! particular to a Unix socket — binding a listener, connecting a client, and
//! the owner-only permissions — and hands every accepted connection to the
//! shared [`serve_connection`](super::serve_connection). The request framing,
//! the dispatch and the client wrappers are the same on every platform and
//! live in [`super`], re-exported here so `ipc::unix::request_status` and its
//! siblings keep resolving.
//!
//! It is reachable only by a process that can open a file inside the agent's
//! owner-only state directory, and the socket itself is created mode `0600`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

use crate::error::{Error, Result};

// The transport-agnostic surface, re-exported so this module is a complete
// view of the local control interface on its own.
pub use super::{
    CONTROL_PROTOCOL, ControlSocketAccess, EXCHANGE_TIMEOUT, ReportSource, is_serving,
    join_network, leave_network, request_status, set_active, set_dns, set_hostname,
};

/// Serves the local control interface on a Unix socket.
#[derive(Debug)]
pub struct ControlSocket {
    path: PathBuf,
    task: Option<JoinHandle<()>>,
}

impl ControlSocket {
    /// Binds the socket and starts serving.
    ///
    /// A socket file left behind by a crashed agent is replaced, but only
    /// after checking that nothing is listening on it, so two live agents
    /// never fight over one path.
    pub async fn bind(
        path: impl AsRef<Path>,
        source: Arc<dyn ReportSource>,
        access: ControlSocketAccess,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            create_parent(parent, &access)?;
        }

        if path.exists() {
            if is_serving(&path).await {
                return Err(Error::StateLocked { path: path.clone() });
            }
            // Nothing is listening, so the file is a leftover.
            std::fs::remove_file(&path).map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })?;
        }

        let listener = UnixListener::bind(&path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        apply_access(&path, &access)?;

        let task = tokio::spawn(serve(listener, source));
        Ok(Self {
            path,
            task: Some(task),
        })
    }

    /// The path being served.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stops serving and removes the socket file.
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Creates the socket's parent directory.
///
/// A group-shared socket must sit in a directory the group can traverse, so it
/// is `0755`; a private socket keeps the owner-only state-directory default.
fn create_parent(parent: &Path, access: &ControlSocketAccess) -> Result<()> {
    match access {
        ControlSocketAccess::Private => crate::storage::create_dir(parent),
        ControlSocketAccess::Group(_) => {
            std::fs::create_dir_all(parent).map_err(|source| Error::Io {
                path: parent.to_path_buf(),
                source,
            })?;
            set_mode(parent, 0o755)
        }
    }
}

/// Applies the access policy to the bound socket.
///
/// Private is owner-only `0600`. Group sets the socket's group to the gid and
/// the mode to `0660`; if the group cannot be set — the agent is not a member,
/// say — it falls back to owner-only rather than leaving the group wrong, so
/// the socket is never more open than intended.
fn apply_access(path: &Path, access: &ControlSocketAccess) -> Result<()> {
    match access {
        ControlSocketAccess::Private => set_mode(path, 0o600),
        ControlSocketAccess::Group(gid) => {
            if let Err(source) = std::os::unix::fs::chown(path, None, Some(*gid)) {
                tracing::warn!(
                    path = %path.display(), gid, %source,
                    "cannot set the control socket group; keeping it owner-only"
                );
                return set_mode(path, 0o600);
            }
            set_mode(path, 0o660)
        }
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|source| {
        Error::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

async fn serve(listener: UnixListener, source: Arc<dyn ReportSource>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let source = Arc::clone(&source);
        tokio::spawn(async move {
            if let Err(err) = super::serve_connection(stream, source).await {
                tracing::debug!(%err, "local control request failed");
            }
        });
    }
}

/// Connects a client to the socket at `path`.
pub(crate) async fn connect(path: &Path) -> Result<UnixStream> {
    UnixStream::connect(path).await.map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Whether an agent is listening on the socket at `path`.
pub(crate) async fn probe(path: &Path) -> bool {
    UnixStream::connect(path).await.is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::time::Duration;

    use super::super::{Request, Response, StatusReport, exchange};
    use super::*;
    use crate::BoxFuture;

    #[tokio::test]
    async fn a_silent_agent_is_reported_rather_than_waited_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        // A socket that accepts and then says nothing, like a wedged agent:
        // the connection succeeds, the answer never comes. Unbounded, this
        // call would never return.
        let _listener = UnixListener::bind(&path).unwrap();

        let error = exchange(&path, &Request::Status, Duration::from_millis(100))
            .await
            .expect_err("a silent agent cannot be reported as healthy");

        match error {
            Error::Timeout { what } => assert!(
                what.contains("control.sock"),
                "the message names what did not answer: {what}"
            ),
            other => panic!("expected a timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_answered_request_is_not_affected_by_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let source: Arc<dyn ReportSource> = Arc::new(|| -> BoxFuture<'static, StatusReport> {
            Box::pin(async { StatusReport::default() })
        });
        let control = ControlSocket::bind(&path, source, ControlSocketAccess::Private)
            .await
            .unwrap();

        let answer = exchange(&path, &Request::Status, EXCHANGE_TIMEOUT)
            .await
            .unwrap();
        assert!(matches!(answer, Response::Status(_)));

        control.shutdown().await;
    }
}
