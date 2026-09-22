//! A named-pipe adapter for the local control interface.
//!
//! The Windows counterpart of [`super::unix`]. It provides only what is
//! particular to a named pipe — creating the server instance, opening a client
//! and turning the state directory path into a pipe name — and hands every
//! accepted connection to the shared [`serve_connection`](super::serve_connection).
//! The framing, the dispatch and the client wrappers are the same on every
//! platform and live in [`super`], re-exported here so `ipc::windows::request_status`
//! and its siblings resolve just as their Unix equivalents do.
//!
//! # From a path to a pipe
//!
//! The rest of the agent addresses the control interface by a filesystem path,
//! the same one a Unix socket would live at. A named pipe has no filesystem
//! path, so the path is hashed into a stable name under `\\.\pipe\`. The agent
//! and a client derive it the same way from the same path, so neither has to
//! be told where the other put it.
//!
//! # Who may connect
//!
//! The pipe rejects clients from other machines, and takes the process's
//! default security, under which the creating user has full access. Narrowing
//! that further with an explicit ACL needs a raw security-descriptor call this
//! crate forbids, so it is not attempted; on a single-user machine, and against
//! other unprivileged users, the default is the practical equivalent of the
//! owner-only Unix socket. There is no leftover to clean up: a pipe exists only
//! while its server does.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, ServerOptions};
use tokio::task::JoinHandle;

use crate::error::{Error, Result};

pub use super::{
    CONTROL_PROTOCOL, EXCHANGE_TIMEOUT, ReportSource, is_serving, join_network, leave_network,
    request_status, set_active, set_dns, set_hostname,
};

/// `ERROR_ACCESS_DENIED`: what creating the first pipe instance returns when
/// one already exists, so another agent already owns the name.
const ERROR_ACCESS_DENIED: i32 = 5;
/// `ERROR_PIPE_BUSY`: every instance is serving a client right now. A server
/// is there; the client only has to wait for a free instance.
const ERROR_PIPE_BUSY: i32 = 231;

/// Serves the local control interface on a named pipe.
#[derive(Debug)]
pub struct ControlSocket {
    path: PathBuf,
    task: Option<JoinHandle<()>>,
}

impl ControlSocket {
    /// Binds the pipe and starts serving.
    ///
    /// Claiming the first instance of the name is what detects a second agent:
    /// if the name already exists, the create is refused and that is reported
    /// as the state being locked, so two live agents never share one pipe.
    pub async fn bind(path: impl AsRef<Path>, source: Arc<dyn ReportSource>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let name = pipe_name(&path);

        let server = match ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&name)
        {
            Ok(server) => server,
            Err(err) if err.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                return Err(Error::StateLocked { path });
            }
            Err(source) => return Err(Error::Io { path, source }),
        };

        let task = tokio::spawn(serve(name, server, source));
        Ok(Self {
            path,
            task: Some(task),
        })
    }

    /// The path the pipe name was derived from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stops serving. The pipe goes with the server, so there is nothing to
    /// remove.
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Accepts one client at a time, keeping a fresh instance ready for the next.
///
/// A named pipe server instance serves a single client, so a new instance is
/// created as soon as one is taken — otherwise a second `tsunagi status` while
/// the first is mid-flight would find nothing listening.
async fn serve(name: String, first: tokio::net::windows::named_pipe::NamedPipeServer, source: Arc<dyn ReportSource>) {
    let mut server = first;
    loop {
        if server.connect().await.is_err() {
            match next_instance(&name) {
                Some(next) => {
                    server = next;
                    continue;
                }
                None => return,
            }
        }
        let connected = server;
        match next_instance(&name) {
            Some(next) => server = next,
            None => {
                // Nothing left to accept the next client on, but the one in
                // hand is still answered before the loop ends.
                let source = Arc::clone(&source);
                tokio::spawn(async move {
                    let _ = super::serve_connection(connected, source).await;
                });
                return;
            }
        }
        let source = Arc::clone(&source);
        tokio::spawn(async move {
            if let Err(err) = super::serve_connection(connected, source).await {
                tracing::debug!(%err, "local control request failed");
            }
        });
    }
}

/// Creates the next pipe instance, or `None` if the name can no longer be
/// served.
fn next_instance(name: &str) -> Option<tokio::net::windows::named_pipe::NamedPipeServer> {
    match ServerOptions::new().reject_remote_clients(true).create(name) {
        Ok(server) => Some(server),
        Err(err) => {
            tracing::debug!(%err, "cannot create the next control pipe instance");
            None
        }
    }
}

/// Connects a client to the pipe for `path`, waiting out a busy pipe.
///
/// The wait is bounded by the caller's exchange timeout, so a pipe that is
/// busy forever is given up on rather than spun on.
pub(crate) async fn connect(path: &Path) -> Result<NamedPipeClient> {
    let name = pipe_name(path);
    loop {
        match ClientOptions::new().open(&name) {
            Ok(client) => return Ok(client),
            Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(source) => {
                return Err(Error::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
}

/// Whether an agent is serving the pipe for `path`.
///
/// A busy pipe still means a server is there; only a name nothing has created
/// counts as not serving.
pub(crate) async fn probe(path: &Path) -> bool {
    let name = pipe_name(path);
    match ClientOptions::new().open(&name) {
        Ok(_) => true,
        Err(err) => err.raw_os_error() == Some(ERROR_PIPE_BUSY),
    }
}

/// The pipe name for a control-socket path.
///
/// A hash rather than the path itself, because a pipe name may not contain the
/// separators and drive letters a path does, and because two agents with
/// different state directories must never collide.
fn pipe_name(path: &Path) -> String {
    let digest = Sha256::digest(path.as_os_str().as_encoded_bytes());
    format!(r"\\.\pipe\tsunagi-{}", hex::encode(&digest[..16]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::time::Duration;

    use super::super::{Request, Response, StatusReport, exchange};
    use super::*;
    use crate::BoxFuture;

    #[test]
    fn one_path_maps_to_one_name_and_two_paths_do_not_collide() {
        let a = pipe_name(Path::new(r"C:\a\agent.sock"));
        let b = pipe_name(Path::new(r"C:\b\agent.sock"));
        assert!(a.starts_with(r"\\.\pipe\tsunagi-"), "{a}");
        assert_eq!(a, pipe_name(Path::new(r"C:\a\agent.sock")));
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn a_request_makes_the_round_trip_over_a_real_pipe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let source: Arc<dyn ReportSource> = Arc::new(|| -> BoxFuture<'static, StatusReport> {
            Box::pin(async { StatusReport::default() })
        });

        assert!(!is_serving(&path).await, "nothing serves the pipe yet");
        let control = ControlSocket::bind(&path, source).await.unwrap();
        assert!(is_serving(&path).await, "the agent serves it now");

        let answer = exchange(&path, &Request::Status, EXCHANGE_TIMEOUT)
            .await
            .unwrap();
        assert!(matches!(answer, Response::Status(_)));

        control.shutdown().await;
    }

    #[tokio::test]
    async fn a_silent_agent_is_reported_rather_than_waited_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        // A server instance that accepts and then never answers, like a
        // wedged agent. Unbounded, the exchange below would never return.
        let name = pipe_name(&path);
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        let _accept = tokio::spawn(async move {
            let _ = server.connect().await;
            // Hold the connection open, answering nothing.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let error = exchange(&path, &Request::Status, Duration::from_millis(200))
            .await
            .expect_err("a silent agent cannot be reported as healthy");
        assert!(matches!(error, Error::Timeout { .. }), "{error:?}");
    }

    #[tokio::test]
    async fn a_second_agent_on_the_same_pipe_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        let source: Arc<dyn ReportSource> = Arc::new(|| -> BoxFuture<'static, StatusReport> {
            Box::pin(async { StatusReport::default() })
        });

        let first = ControlSocket::bind(&path, Arc::clone(&source)).await.unwrap();
        let second = ControlSocket::bind(&path, source).await;
        assert!(
            matches!(second, Err(Error::StateLocked { .. })),
            "{second:?}"
        );

        first.shutdown().await;
    }
}
