//! A Unix socket adapter for the local control interface.
//!
//! One of possibly several adapters; see [`super`]. It serves exactly the
//! requests in [`Request`] and nothing else, and it is reachable only by a
//! process that can open a file inside the agent's owner-only state
//! directory.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

use crate::BoxFuture;
use crate::error::{Error, Result};

use super::{MAX_MESSAGE_LEN, Request, Response, StatusReport};

/// Builds the report that answers a status request.
///
/// Supplied by the caller, because only the caller knows which plugins are
/// running and what they can report. That is what keeps this module free of
/// any knowledge of them.
pub trait ReportSource: Send + Sync + 'static {
    /// Produces a fresh report.
    fn report(&self) -> BoxFuture<'_, StatusReport>;

    /// Changes the name the agent answers to, returning the accepted form.
    ///
    /// Defaulted to a refusal so that a source which only reports — the
    /// closure impl below, and every test that uses it — stays valid and
    /// says plainly that it cannot do this, rather than appearing to.
    fn set_hostname(
        &self,
        _hostname: String,
    ) -> BoxFuture<'_, std::result::Result<String, String>> {
        Box::pin(async move { Err("this agent cannot change its hostname".to_string()) })
    }
}

impl<F> ReportSource for F
where
    F: Fn() -> BoxFuture<'static, StatusReport> + Send + Sync + 'static,
{
    fn report(&self) -> BoxFuture<'_, StatusReport> {
        (self)()
    }
}

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
    pub async fn bind(path: impl AsRef<Path>, source: Arc<dyn ReportSource>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            crate::storage::create_dir(parent)?;
        }

        if path.exists() {
            match UnixStream::connect(&path).await {
                Ok(_) => {
                    return Err(Error::StateLocked { path: path.clone() });
                }
                // Nothing is listening, so the file is a leftover.
                Err(_) => {
                    std::fs::remove_file(&path).map_err(|source| Error::Io {
                        path: path.clone(),
                        source,
                    })?;
                }
            }
        }

        let listener = UnixListener::bind(&path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        restrict(&path)?;

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

#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
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
            if let Err(err) = handle(stream, source).await {
                tracing::debug!(%err, "local control request failed");
            }
        });
    }
}

async fn handle(mut stream: UnixStream, source: Arc<dyn ReportSource>) -> Result<()> {
    // Bounded, so a connection that sends nothing cannot hold a task open.
    // Only the wait for the request: building the report afterwards takes as
    // long as it takes, and cutting it off would answer a live client with a
    // closed socket.
    let request: Request =
        match tokio::time::timeout(EXCHANGE_TIMEOUT, read_message(&mut stream)).await {
            Ok(request) => request?,
            Err(_) => {
                return Err(Error::Timeout {
                    what: "a local control connection".to_string(),
                });
            }
        };
    let response = match request {
        Request::Status => Response::Status(Box::new(source.report().await)),
        Request::SetHostname(hostname) => match source.set_hostname(hostname).await {
            Ok(accepted) => Response::Hostname(accepted),
            Err(reason) => Response::Error(reason),
        },
    };
    write_message(&mut stream, &response).await
}

/// How long either end waits for the other.
///
/// A local answer comes from memory, so anything this slow means the agent is
/// wedged rather than busy. Saying so beats waiting: unbounded, one wedged
/// runtime leaves `tsunagi status` hanging with nothing on screen and no way
/// out but Ctrl-C.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);

/// Asks a running agent for its status.
pub async fn request_status(path: impl AsRef<Path>) -> Result<StatusReport> {
    let path = path.as_ref();
    match exchange(path, &Request::Status, EXCHANGE_TIMEOUT).await? {
        Response::Status(report) => Ok(*report),
        Response::Error(reason) => Err(Error::Storage(reason)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

/// Asks a running agent to answer to a different name.
///
/// Returns the name it accepted, which is the canonical form of what was
/// asked for and may differ from it.
pub async fn set_hostname(path: impl AsRef<Path>, hostname: &str) -> Result<String> {
    let path = path.as_ref();
    let request = Request::SetHostname(hostname.to_string());
    match exchange(path, &request, EXCHANGE_TIMEOUT).await? {
        Response::Hostname(accepted) => Ok(accepted),
        Response::Error(reason) => Err(Error::Storage(reason)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
    }
}

/// Connects, sends one request and reads the answer, all within `within`.
///
/// The bound covers the whole exchange rather than each read: an agent that
/// answers the header and then stops is as stuck as one that never answers.
async fn exchange(path: &Path, request: &Request, within: Duration) -> Result<Response> {
    let attempt = async {
        let mut stream = UnixStream::connect(path)
            .await
            .map_err(|source| Error::Io {
                path: path.to_path_buf(),
                source,
            })?;
        write_message(&mut stream, request).await?;
        read_message::<Response>(&mut stream).await
    };

    match tokio::time::timeout(within, attempt).await {
        Ok(result) => result,
        Err(_) => Err(Error::Timeout {
            what: format!("the agent at {}", path.display()),
        }),
    }
}

/// Marks the wire format of the local control socket.
///
/// `b"TSN"` followed by the version, so a mismatch is recognised as one
/// instead of being read as a length. The encoding is postcard, which is not
/// self-describing: adding a field to a report changes how the bytes parse,
/// and without this a client one build ahead of its agent reports something
/// like "Found an Option discriminant that wasn't 0 or 1" — which says
/// nothing about the actual problem, that the two are different builds.
///
/// Bump it whenever [`Request`], [`Response`] or anything they contain
/// changes shape.
pub const CONTROL_PROTOCOL: u32 = u32::from_be_bytes([b'T', b'S', b'N', 7]);

async fn write_message<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let encoded = postcard::to_stdvec(value)
        .map_err(|err| Error::Storage(format!("cannot encode a control message: {err}")))?;
    if encoded.len() > MAX_MESSAGE_LEN {
        return Err(Error::Storage("control message is too large".into()));
    }
    let len = encoded.len() as u32;
    stream
        .write_all(&CONTROL_PROTOCOL.to_be_bytes())
        .await
        .map_err(io_error)?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(io_error)?;
    stream.write_all(&encoded).await.map_err(io_error)?;
    stream.flush().await.map_err(io_error)
}

async fn read_message<T: for<'de> serde::Deserialize<'de>>(stream: &mut UnixStream) -> Result<T> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(io_error)?;
    let version = u32::from_be_bytes(header);
    if version != CONTROL_PROTOCOL {
        return Err(Error::Storage(format!(
            "the other end speaks control protocol {version:#010x} and this build speaks \
             {CONTROL_PROTOCOL:#010x}; they are different builds of tsunagi, so restart the \
             agent with the binary you are running now"
        )));
    }

    stream.read_exact(&mut header).await.map_err(io_error)?;
    let len = u32::from_be_bytes(header) as usize;
    // Checked before allocating, exactly as on the network.
    if len > MAX_MESSAGE_LEN {
        return Err(Error::Storage(format!(
            "control message of {len} bytes exceeds the {MAX_MESSAGE_LEN} byte limit"
        )));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.map_err(io_error)?;
    postcard::from_bytes(&payload)
        .map_err(|err| Error::Storage(format!("cannot decode a control message: {err}")))
}

fn io_error(source: std::io::Error) -> Error {
    Error::Io {
        path: PathBuf::from("<local control socket>"),
        source,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

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
        let control = ControlSocket::bind(&path, source).await.unwrap();

        let answer = exchange(&path, &Request::Status, EXCHANGE_TIMEOUT)
            .await
            .unwrap();
        assert!(matches!(answer, Response::Status(_)));

        control.shutdown().await;
    }
}
