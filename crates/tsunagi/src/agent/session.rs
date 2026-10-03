//! One authenticated session with one peer, in one network.
//!
//! A session owns a reader task and a writer task over a single QUIC
//! bidirectional stream. Splitting them keeps both halves simple and avoids
//! cancelling a partially consumed frame, which stream reads do not tolerate.
//!
//! Every inbound message is re-checked against the session's network id, so an
//! authenticated session for one network can never deliver into another.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Limits;
use crate::dataplane::PluginCapability;
use crate::error::ProtocolError;
use crate::identity::NetworkId;
use crate::proto::handshake::Role;
use crate::proto::message::{ControlMessage, Envelope, decode, validate};
use crate::proto::{read_frame, write_frame};

use super::shutdown::Shutdown;

/// What a session task reports back to its network runtime.
#[derive(Debug)]
pub(crate) enum SessionEvent {
    /// A valid control message arrived.
    Message {
        /// Which session instance produced this.
        session_id: u64,
        /// The peer.
        peer: EndpointId,
        /// The decoded message.
        message: ControlMessage,
        /// Payload bytes read off the wire.
        bytes: usize,
    },
    /// The peer sent something the protocol does not allow.
    Violation {
        /// Which session instance produced this.
        session_id: u64,
        /// The peer.
        peer: EndpointId,
        /// What was wrong.
        error: ProtocolError,
    },
    /// The session ended.
    Closed {
        /// Which session instance ended.
        session_id: u64,
        /// The peer.
        peer: EndpointId,
        /// Why it ended.
        reason: String,
    },
}

/// A live session, as held by the network runtime.
#[derive(Debug)]
pub(crate) struct Session {
    pub(crate) id: u64,
    pub(crate) peer: EndpointId,
    pub(crate) role: Role,
    pub(crate) established: Instant,
    pub(crate) conn: Connection,
    /// Already encoded frame payloads, so the runtime can account for the exact
    /// number of control bytes it queues.
    pub(crate) outbound: mpsc::Sender<Vec<u8>>,
    pub(crate) hostname: Option<String>,
    pub(crate) capabilities: Vec<PluginCapability>,
    pub(crate) broadcast: bool,
    /// The peer offers itself as an exit node in this network.
    pub(crate) exit_node: bool,
    pub(crate) messages_sent: u64,
    pub(crate) messages_received: u64,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_received: u64,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
    path_monitor: JoinHandle<()>,
    shutdown: Shutdown,
}

impl Session {
    /// Signals all tasks to stop and waits for them, with a bounded grace
    /// period.
    ///
    /// A peer that stops reading must not be able to hold up shutdown, so the
    /// tasks are aborted if they do not wind down in time.
    pub(crate) async fn stop(self) {
        let Session {
            conn,
            reader,
            writer,
            path_monitor,
            shutdown,
            ..
        } = self;
        shutdown.trigger();
        // Closing the connection unblocks a reader parked on the stream.
        conn.close(0u32.into(), b"session stopped by local agent");

        let reader_abort = reader.abort_handle();
        let writer_abort = writer.abort_handle();
        let path_abort = path_monitor.abort_handle();
        let joined = tokio::time::timeout(STOP_GRACE, async move {
            let _ = reader.await;
            let _ = writer.await;
            let _ = path_monitor.await;
        })
        .await;
        if joined.is_err() {
            tracing::debug!("session tasks did not wind down in time; aborting them");
            reader_abort.abort();
            writer_abort.abort();
            path_abort.abort();
        }
    }

    /// Aborts all tasks without waiting. Used on replacement.
    pub(crate) fn abort(&self) {
        self.shutdown.trigger();
        self.reader.abort();
        self.writer.abort();
        self.path_monitor.abort();
    }
}

/// How long a stopping session may take to wind down before its tasks are
/// aborted. Shutdown must be bounded even if a peer stops reading.
const STOP_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Source of monotonically increasing session instance ids.
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Starts the reader and writer tasks for an authenticated stream.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn(
    network_id: NetworkId,
    peer: EndpointId,
    role: Role,
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    limits: Arc<Limits>,
    events: mpsc::Sender<SessionEvent>,
    parent_shutdown: Shutdown,
) -> Session {
    let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    let shutdown = Shutdown::new();
    let (outbound_tx, outbound_rx) = mpsc::channel(limits.session_send_queue);

    let writer = tokio::spawn(writer_task(
        send,
        outbound_rx,
        Arc::clone(&limits),
        shutdown.clone(),
        parent_shutdown.clone(),
    ));

    let path_conn = conn.clone();
    let path_shutdown = shutdown.clone();
    let path_parent = parent_shutdown.clone();
    let path_monitor = tokio::spawn(async move {
        use tokio_stream::StreamExt;
        let mut events = path_conn.path_events();
        loop {
            tokio::select! {
                biased;
                _ = path_shutdown.wait() => break,
                _ = path_parent.wait() => break,
                ev = events.next() => {
                    match ev {
                        Some(iroh::endpoint::PathEvent::Selected { remote_addr, local_addr, .. }) => {
                            tracing::debug!(
                                peer = %peer.fmt_short(),
                                remote = %remote_addr,
                                local = ?local_addr,
                                "Connection path selected (direct / relay / hole punch switch)"
                            );
                        }
                        Some(iroh::endpoint::PathEvent::Opened { remote_addr, .. }) => {
                            tracing::debug!(
                                peer = %peer.fmt_short(),
                                remote = %remote_addr,
                                "Network path opened to peer"
                            );
                        }
                        Some(iroh::endpoint::PathEvent::Closed { remote_addr, .. }) => {
                            tracing::debug!(
                                peer = %peer.fmt_short(),
                                remote = %remote_addr,
                                "Network path closed for peer"
                            );
                        }
                        Some(iroh::endpoint::PathEvent::Lagged { missed, .. }) => {
                            tracing::trace!(peer = %peer.fmt_short(), missed, "Path events lagged");
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
            }
        }
    });

    let reader = tokio::spawn(reader_task(
        id,
        network_id,
        peer,
        recv,
        limits,
        events,
        shutdown.clone(),
        parent_shutdown,
    ));

    Session {
        id,
        peer,
        role,
        established: Instant::now(),
        conn,
        outbound: outbound_tx,
        hostname: None,
        capabilities: Vec::new(),
        broadcast: false,
        exit_node: false,
        messages_sent: 0,
        messages_received: 0,
        bytes_sent: 0,
        bytes_received: 0,
        reader,
        writer,
        path_monitor,
        shutdown,
    }
}

async fn writer_task(
    mut send: SendStream,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    limits: Arc<Limits>,
    shutdown: Shutdown,
    parent: Shutdown,
) {
    loop {
        let encoded = tokio::select! {
            biased;
            _ = shutdown.wait() => break,
            _ = parent.wait() => break,
            encoded = outbound.recv() => match encoded {
                Some(encoded) => encoded,
                None => break,
            },
        };

        // The write must stay cancellable: shutting the session down cannot
        // wait for a peer that has stopped reading. Abandoning a half written
        // frame is fine, because the session is going away with it.
        let write = tokio::time::timeout(
            limits.write_timeout,
            write_frame(&mut send, &encoded, limits.max_frame_len),
        );
        let result = tokio::select! {
            biased;
            _ = shutdown.wait() => break,
            _ = parent.wait() => break,
            result = write => result,
        };
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                tracing::debug!(%err, "control stream write failed");
                break;
            }
            Err(_) => {
                tracing::debug!("control stream write timed out");
                break;
            }
        }
    }
    let _ = send.finish();
}

#[allow(clippy::too_many_arguments)]
async fn reader_task(
    session_id: u64,
    network_id: NetworkId,
    peer: EndpointId,
    mut recv: RecvStream,
    limits: Arc<Limits>,
    events: mpsc::Sender<SessionEvent>,
    shutdown: Shutdown,
    parent: Shutdown,
) {
    let reason = loop {
        let frame = tokio::select! {
            biased;
            _ = shutdown.wait() => break "stopped locally".to_string(),
            _ = parent.wait() => break "network deactivated".to_string(),
            frame = read_frame(&mut recv, limits.max_frame_len) => frame,
        };

        let payload = match frame {
            Ok(payload) => payload,
            Err(ProtocolError::StreamClosed) => break "peer closed the control stream".to_string(),
            Err(ProtocolError::Stream(err)) => {
                // The transport went away. That is a disconnect, not a peer
                // misbehaving, so it ends the session without being counted as
                // a protocol violation.
                break format!("control stream error: {err}");
            }
            Err(err) => {
                // A framing violation ends this session. Framing errors are not
                // recoverable mid-stream: the next bytes have no known meaning.
                let text = err.to_string();
                let _ = events
                    .send(SessionEvent::Violation {
                        session_id,
                        peer,
                        error: err,
                    })
                    .await;
                break text;
            }
        };

        let bytes = payload.len();
        let envelope: Envelope = match decode(&payload) {
            Ok(envelope) => envelope,
            Err(err) => {
                let _ = events
                    .send(SessionEvent::Violation {
                        session_id,
                        peer,
                        error: err,
                    })
                    .await;
                break "malformed control frame".to_string();
            }
        };

        // Network isolation: a session authenticated for one network must never
        // deliver a message belonging to another.
        if envelope.network_id != *network_id.as_bytes() {
            let _ = events
                .send(SessionEvent::Violation {
                    session_id,
                    peer,
                    error: ProtocolError::NetworkMismatch,
                })
                .await;
            break "network id mismatch on an authenticated session".to_string();
        }

        if let Err(err) = validate(&envelope.message, &limits) {
            let _ = events
                .send(SessionEvent::Violation {
                    session_id,
                    peer,
                    error: err,
                })
                .await;
            continue;
        }

        if events
            .send(SessionEvent::Message {
                session_id,
                peer,
                message: envelope.message,
                bytes,
            })
            .await
            .is_err()
        {
            break "network runtime stopped".to_string();
        }
    };

    // Best effort: the runtime may already have stopped draining this channel
    // while it tears the network down, and a closing session must not block on
    // that.
    let _ = events.try_send(SessionEvent::Closed {
        session_id,
        peer,
        reason,
    });
}
