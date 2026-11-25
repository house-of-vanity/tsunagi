//! A dedicated local connection is the lifetime of one traffic window.
use super::{
    EXCHANGE_TIMEOUT, Error, Path, Request, Response, Result, read_message, transport,
    write_message,
};
use crate::traffic::{TrafficSnapshot, TrafficSubscription};
use std::{future::Future, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(unix)]
type Socket = tokio::net::UnixStream;
#[cfg(windows)]
type Socket = tokio::net::windows::named_pipe::NamedPipeClient;

async fn bounded<T>(duration: Duration, f: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(duration, f)
        .await
        .map_err(|_| Error::Timeout {
            what: "local traffic monitor".into(),
        })?
}

/// A local monitor stream. Dropping it releases the agent's interval buffer.
pub struct TrafficStream(Socket);
impl TrafficStream {
    /// Starts observing now, independently of any other open window.
    pub async fn open(path: &Path) -> Result<Self> {
        bounded(EXCHANGE_TIMEOUT, async {
            let mut socket = transport::connect(path).await?;
            write_message(&mut socket, &Request::WatchTraffic).await?;
            match read_message(&mut socket).await? {
                Response::TrafficReady => Ok(Self(socket)),
                Response::Error(reason) => Err(Error::TrafficMonitor(reason)),
                _ => Err(Error::TrafficMonitor(
                    "Unexpected answer opening traffic monitor".into(),
                )),
            }
        })
        .await
    }

    /// Drains only this reader's interval.
    pub async fn snapshot(&mut self) -> Result<TrafficSnapshot> {
        bounded(EXCHANGE_TIMEOUT, async {
            write_message(&mut self.0, &0u8).await?;
            read_message(&mut self.0).await
        })
        .await
    }
}

pub(super) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut socket: S,
    sub: TrafficSubscription,
) -> Result<()> {
    bounded(
        EXCHANGE_TIMEOUT,
        write_message(&mut socket, &Response::TrafficReady),
    )
    .await?;
    loop {
        // A wedged or suspended client cannot keep the collector running indefinitely.
        let token: u8 = bounded(Duration::from_secs(15), read_message(&mut socket)).await?;
        if token != 0 {
            return Err(Error::TrafficMonitor("Invalid monitor poll".into()));
        }
        bounded(
            EXCHANGE_TIMEOUT,
            write_message(&mut socket, &sub.snapshot()),
        )
        .await?;
    }
}
