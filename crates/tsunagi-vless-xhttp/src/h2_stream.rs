//! Adapted from Shoes v0.3.8, src/http2/stream.rs (MIT).
use bytes::Bytes;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct H2MultiStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    recv_buf: Bytes,
    shutdown_sent: bool,
}
impl H2MultiStream {
    pub(crate) fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            recv_buf: Bytes::new(),
            shutdown_sent: false,
        }
    }
}
impl AsyncRead for H2MultiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Empty DATA is not EOF. Bound work per poll even for a padding-only peer.
        for _ in 0..32 {
            if !self.recv_buf.is_empty() {
                let count = self.recv_buf.len().min(buf.remaining());
                buf.put_slice(&self.recv_buf.split_to(count));
                self.recv
                    .flow_control()
                    .release_capacity(count)
                    .map_err(io::Error::other)?;
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.recv.poll_data(cx)) {
                Some(Ok(data)) => self.recv_buf = data,
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => return Poll::Ready(Ok(())),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for H2MultiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.shutdown_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let wanted = buf.len().min(16 * 1024);
        let send = &mut self.send;
        send.reserve_capacity(wanted);
        loop {
            let capacity = send.capacity();
            if capacity != 0 {
                let count = wanted.min(capacity);
                send.send_data(Bytes::copy_from_slice(&buf[..count]), false)
                    .map_err(io::Error::other)?;
                return Poll::Ready(Ok(count));
            }
            match std::task::ready!(send.poll_capacity(cx)) {
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // h2 has no per-stream flush; the connection driver handles transmission
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_sent {
            self.send
                .send_data(Bytes::new(), true)
                .map_err(io::Error::other)?;
            self.shutdown_sent = true;
        }

        // Don't wait for peer ACK; the connection driver transmits END_STREAM reliably
        Poll::Ready(Ok(()))
    }
}
