//! Tie an HTTP/2 connection or record driver to its negotiated stream.
use crate::{ByteStream, Stream};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Driven<S> {
    inner: S,
    driver: tokio::task::JoinHandle<()>,
}
impl<S> Drop for Driven<S> {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
/// Closing a link cancels its driver even when the peer has stopped reading.
pub fn driven<S: ByteStream + 'static>(
    inner: S,
    driver: impl Future<Output = ()> + Send + 'static,
) -> Stream {
    Box::new(Driven {
        inner,
        driver: tokio::spawn(driver),
    })
}
impl<S: ByteStream> AsyncRead for Driven<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: ByteStream> AsyncWrite for Driven<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
