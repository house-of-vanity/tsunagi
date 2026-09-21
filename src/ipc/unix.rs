//! A Unix socket adapter for the local control interface.
//!
//! One of possibly several adapters; see [`super`]. It serves exactly the
//! requests in [`Request`] and nothing else, and it is reachable only by a
//! process that can open a file inside the agent's owner-only state
//! directory.

use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    let request: Request = read_message(&mut stream).await?;
    let response = match request {
        Request::Status => Response::Status(Box::new(source.report().await)),
        Request::SetHostname(hostname) => match source.set_hostname(hostname).await {
            Ok(accepted) => Response::Hostname(accepted),
            Err(reason) => Response::Error(reason),
        },
    };
    write_message(&mut stream, &response).await
}

/// Asks a running agent for its status.
pub async fn request_status(path: impl AsRef<Path>) -> Result<StatusReport> {
    let path = path.as_ref();
    let mut stream = UnixStream::connect(path)
        .await
        .map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
    write_message(&mut stream, &Request::Status).await?;
    match read_message::<Response>(&mut stream).await? {
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
    let mut stream = UnixStream::connect(path)
        .await
        .map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
    write_message(&mut stream, &Request::SetHostname(hostname.to_string())).await?;
    match read_message::<Response>(&mut stream).await? {
        Response::Hostname(accepted) => Ok(accepted),
        Response::Error(reason) => Err(Error::Storage(reason)),
        other => Err(Error::Storage(format!("unexpected answer: {other:?}"))),
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
pub const CONTROL_PROTOCOL: u32 = u32::from_be_bytes([b'T', b'S', b'N', 3]);

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
