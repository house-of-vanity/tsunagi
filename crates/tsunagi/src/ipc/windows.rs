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
//! The pipe rejects clients from other machines (`reject_remote_clients(true)`).
//! An explicit SDDL security descriptor grants Full Control to Administrators
//! and LocalSystem, while granting Read and Write (`GRGW`) to all local users
//! with a Medium Integrity SACL label (`S:(ML;;NW;;;ME)`). This allows unprivileged
//! user-space tools (such as tray applications, status monitors, or CLI commands
//! launched by regular users) to connect to the agent even when the agent was
//! started by an elevated Administrator or as a system service.
//! A permission denial is reported as such, never as an absent agent.

#![allow(unsafe_code)]

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

/// `ERROR_ACCESS_DENIED`: creating a first instance finds an existing pipe,
/// or a client cannot access an existing pipe with its current privileges.
const ERROR_ACCESS_DENIED: i32 = 5;
/// `ERROR_PIPE_BUSY`: every instance is serving a client right now. A server
/// is there; the client only has to wait for a free instance.
const ERROR_PIPE_BUSY: i32 = 231;

/// RAII wrapper for Windows named pipe security attributes with permissive local ACL.
///
/// SDDL specification:
/// - `D:(A;;GRGW;;;WD)`: DACL allows Generic Read and Generic Write to Everyone (`WD`).
///   Full control (`GA`) remains reserved to Administrators and LocalSystem.
/// - `(A;;GA;;;BA)`: DACL allows Generic All to Builtin Administrators (`BA`).
/// - `(A;;GA;;;SY)`: DACL allows Generic All to LocalSystem (`SY`).
/// - `S:(ML;;NW;;;ME)`: SACL Mandatory Label with Medium Integrity (`ME`) and No Write Up (`NW`).
///   This allows unprivileged user-space processes (Medium Integrity) to write to the
///   named pipe even when the agent runs as an elevated Administrator (High Integrity).
#[derive(Debug)]
struct PipeSecurityAttributes {
    attrs: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

impl PipeSecurityAttributes {
    fn new() -> Result<Self> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };

        const SDDL: &str = "D:(A;;GRGW;;;WD)(A;;GA;;;BA)(A;;GA;;;SY)S:(ML;;NW;;;ME)";
        let wide: Vec<u16> = OsStr::new(SDDL)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut p_sd = std::ptr::null_mut();
        // SAFETY: We pass a valid null-terminated wide string, standard revision 1,
        // and a valid pointer to receive the descriptor.
        let success = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut p_sd,
                std::ptr::null_mut(),
            )
        };

        if success == 0 || p_sd.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(Error::Storage(format!(
                "cannot create pipe security descriptor: {err}"
            )));
        }

        let attrs = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: p_sd,
            bInheritHandle: 0,
        };

        Ok(Self { attrs })
    }

    fn as_raw_mut(&mut self) -> *mut std::ffi::c_void {
        &mut self.attrs as *mut _ as *mut std::ffi::c_void
    }
}

impl Drop for PipeSecurityAttributes {
    fn drop(&mut self) {
        if !self.attrs.lpSecurityDescriptor.is_null() {
            // SAFETY: The descriptor was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW
            // and must be freed with LocalFree.
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(self.attrs.lpSecurityDescriptor);
            }
            self.attrs.lpSecurityDescriptor = std::ptr::null_mut();
        }
    }
}

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

        let mut sec_attrs = PipeSecurityAttributes::new()?;
        // SAFETY: sec_attrs points to valid initialized SECURITY_ATTRIBUTES.
        let server = match unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(&name, sec_attrs.as_raw_mut())
        } {
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
async fn serve(
    name: String,
    first: tokio::net::windows::named_pipe::NamedPipeServer,
    source: Arc<dyn ReportSource>,
) {
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
    let mut sec_attrs = match PipeSecurityAttributes::new() {
        Ok(attrs) => attrs,
        Err(err) => {
            tracing::debug!(%err, "cannot build pipe security attributes for next instance");
            return None;
        }
    };
    // SAFETY: sec_attrs points to valid initialized SECURITY_ATTRIBUTES.
    match unsafe {
        ServerOptions::new()
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, sec_attrs.as_raw_mut())
    } {
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
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(Error::Io {
                    path: path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "the agent's control pipe exists, but Windows denied access. \
                             Run this command as the same Windows user and with the same \
                             elevation as `tsunagi up` (use an administrator terminal if \
                             the agent is elevated). Windows error: {err}"
                        ),
                    ),
                });
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
/// A busy or inaccessible pipe still means a server is there. In particular,
/// access denied must not send a mutating command down the offline path,
/// where it would only produce a misleading state-directory lock error.
pub(crate) async fn probe(path: &Path) -> bool {
    let name = pipe_name(path);
    match ClientOptions::new().open(&name) {
        Ok(_) => true,
        Err(err) => {
            err.raw_os_error() == Some(ERROR_PIPE_BUSY)
                || err.kind() == std::io::ErrorKind::PermissionDenied
        }
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
    async fn an_inaccessible_agent_is_not_mistaken_for_an_absent_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.sock");
        // An outbound-only pipe denies the client's duplex open even when
        // both processes have the same privileges. This exercises the same
        // Windows error as a client unable to access an elevated agent,
        // without requiring elevation or changing any ACLs.
        let _server = ServerOptions::new()
            .first_pipe_instance(true)
            .access_inbound(false)
            .create(pipe_name(&path))
            .unwrap();

        assert!(is_serving(&path).await, "access denied is not absence");
        for error in [
            request_status(&path).await.unwrap_err(),
            join_network(&path, "test", "local-ipc-test-secret")
                .await
                .unwrap_err(),
            set_dns(&path, false, None).await.unwrap_err(),
        ] {
            let Error::Io { source, .. } = error else {
                panic!("expected an access error, got {error}");
            };
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            let message = source.to_string();
            assert!(message.contains("same Windows user"), "{message}");
            assert!(message.contains("administrator"), "{message}");
            assert!(!message.contains("local-ipc-test-secret"), "{message}");
        }
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

        let first = ControlSocket::bind(&path, Arc::clone(&source))
            .await
            .unwrap();
        let second = ControlSocket::bind(&path, source).await;
        assert!(
            matches!(second, Err(Error::StateLocked { .. })),
            "{second:?}"
        );

        first.shutdown().await;
    }
}
