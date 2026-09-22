//! A data plane transport built on iroh.
//!
//! This is where the data plane gets NAT traversal from. iroh hole punches a
//! direct path between two peers when it can and falls back to a relay when it
//! cannot, so every plugin inherits that without implementing STUN, ICE or a
//! relay of its own.
//!
//! Data connections are separate from control connections in every way that
//! matters: their own ALPN ([`DATA_ALPN`]), their own QUIC connection, their
//! own congestion control. They carry one plugin protocol for one network.
//! A data connection that breaks or floods cannot disturb the control plane.
//!
//! Packets travel as QUIC datagrams: unreliable and unordered, which is what a
//! tunnelled UDP protocol wants, and free of the head-of-line blocking a
//! stream would add.
//!
//! The channel is authenticated exactly like a control connection — the same
//! membership handshake, bound to the same network — so a data link cannot be
//! opened by someone who does not know the network secret.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};

use crate::BoxFuture;
use crate::config::{DATA_REASSEMBLY_TTL, Limits, MAX_DATA_DATAGRAM, MAX_DATA_FRAGMENTS};
use crate::error::ProtocolError;
use crate::identity::{NetworkId, NetworkKeys};
use crate::net::EndpointAdapter;
use crate::proto::handshake;
use crate::proto::message::{
    DATA_ALPN, DataOpen, DataOpenAck, MAX_DATA_PROTOCOL_LEN, decode, encode,
};
use crate::proto::{read_frame, write_frame};

use super::fragments::{self, Reassembler};
use super::{InboundLink, PacketLink, PacketTransport, SharedLink, TransportError};

/// What the iroh transport needs from the agent.
///
/// Implemented by the agent, which is the only thing that knows which networks
/// are active and which plugin protocols are served.
pub trait TransportContext: Send + Sync + std::fmt::Debug + 'static {
    /// Key material of every network that is active right now.
    ///
    /// Taken as one snapshot because the membership handshake resolves the
    /// requested network synchronously, exactly as the control plane's accept
    /// path does.
    fn snapshot<'a>(&'a self) -> BoxFuture<'a, HashMap<NetworkId, NetworkKeys>>;

    /// Whether a plugin protocol is served in a network.
    fn serves<'a>(&'a self, network: NetworkId, protocol: &'a str) -> BoxFuture<'a, bool>;
}

/// One authenticated datagram channel over an iroh connection.
#[derive(Debug)]
pub struct IrohLink {
    network: NetworkId,
    peer: EndpointId,
    conn: Connection,
    max_datagram: usize,
    next_packet: AtomicU64,
    reassembly: tokio::sync::Mutex<Reassembler>,
    // Kept alive so the peer sees the channel as open; the connection closes
    // when the link is dropped.
    _send: tokio::sync::Mutex<SendStream>,
    _recv: tokio::sync::Mutex<RecvStream>,
}

impl IrohLink {
    fn new(
        network: NetworkId,
        peer: EndpointId,
        conn: Connection,
        peer_limit: usize,
        send: SendStream,
        recv: RecvStream,
    ) -> Self {
        // The negotiated limit is for reassembled payloads, never a snapshot
        // of the initial path (which may still be a relay or another VPN).
        let max_datagram = MAX_DATA_DATAGRAM.min(peer_limit);
        Self {
            network,
            peer,
            conn,
            max_datagram,
            next_packet: AtomicU64::new(0),
            reassembly: tokio::sync::Mutex::new(Reassembler::default()),
            _send: tokio::sync::Mutex::new(send),
            _recv: tokio::sync::Mutex::new(recv),
        }
    }
}

impl PacketLink for IrohLink {
    fn network(&self) -> NetworkId {
        self.network
    }

    fn peer(&self) -> EndpointId {
        self.peer
    }

    fn max_datagram_size(&self) -> usize {
        self.max_datagram
    }

    fn send(&self, payload: Bytes) -> Result<(), TransportError> {
        if payload.len() > self.max_datagram {
            return Err(TransportError::TooLarge {
                size: payload.len(),
                limit: self.max_datagram,
            });
        }
        let id = self.next_packet.fetch_add(1, Ordering::Relaxed);
        let mut offset: usize = 0;
        let mut attempts = 0;
        // Re-read the current path's capacity for every fragment. A migration
        // can shrink it even between two send_datagram calls.
        for _ in 0..MAX_DATA_FRAGMENTS {
            loop {
                let capacity = self
                    .conn
                    .max_datagram_size()
                    .unwrap_or(0)
                    .checked_sub(fragments::HEADER)
                    .filter(|n| *n > 0)
                    .ok_or_else(|| {
                        TransportError::Other("QUIC path cannot carry data fragments".into())
                    })?;
                let end = offset.saturating_add(capacity).min(payload.len());
                let frame = fragments::encode(id, payload.len(), offset, &payload[offset..end]);
                match self.conn.send_datagram(frame) {
                    Ok(()) => {
                        offset = end;
                        break;
                    }
                    Err(iroh::endpoint::SendDatagramError::TooLarge) if attempts < 3 => {
                        attempts += 1;
                    }
                    Err(iroh::endpoint::SendDatagramError::ConnectionLost(_)) => {
                        return Err(TransportError::Closed);
                    }
                    Err(err) => return Err(TransportError::Other(err.to_string())),
                }
            }
            if offset == payload.len() {
                return Ok(());
            }
        }
        Err(TransportError::Other(
            "QUIC path needs too many fragments".into(),
        ))
    }

    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move {
            let mut reassembly = self.reassembly.lock().await;
            loop {
                match tokio::time::timeout(DATA_REASSEMBLY_TTL, self.conn.read_datagram()).await {
                    Ok(Ok(frame)) => {
                        if let Some(packet) = reassembly.push(frame, tokio::time::Instant::now()) {
                            return Some(packet);
                        }
                    }
                    Ok(Err(_)) => {
                        *reassembly = Reassembler::default();
                        return None;
                    }
                    Err(_) => reassembly.expire(tokio::time::Instant::now()),
                }
            }
        })
    }

    fn closed(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let _ = self.conn.closed().await;
        })
    }

    fn is_closed(&self) -> bool {
        self.conn.close_reason().is_some()
    }

    fn path_description(&self) -> String {
        // Report what iroh actually knows, never a guess.
        let snapshot = crate::net::snapshot_connection(&self.conn);
        match snapshot.paths.iter().find(|path| path.is_selected) {
            Some(path) => format!("{} via {}", snapshot.transport, path.remote),
            None => format!("{}, no selected path yet", snapshot.transport),
        }
    }
}

/// Opens and accepts data plane links over iroh.
#[derive(Debug, Clone)]
pub struct IrohTransport {
    adapter: EndpointAdapter,
    limits: Arc<Limits>,
    lookup: Arc<dyn TransportContext>,
}

impl IrohTransport {
    /// Creates a transport on an existing endpoint.
    pub fn new(
        adapter: EndpointAdapter,
        limits: Arc<Limits>,
        lookup: Arc<dyn TransportContext>,
    ) -> Self {
        Self {
            adapter,
            limits,
            lookup,
        }
    }

    /// Completes an inbound data connection that the accept loop routed here.
    ///
    /// The membership handshake runs first, exactly as on a control
    /// connection, so an unauthenticated caller never reaches a plugin.
    pub async fn accept(&self, conn: Connection) -> Result<InboundLink, TransportError> {
        let peer = conn.remote_id();
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|err| TransportError::Other(format!("no data channel stream: {err}")))?;

        let local_id = self.adapter.endpoint_id();
        let known = self.lookup.snapshot().await;
        let outcome = handshake::respond(
            &conn,
            &mut send,
            &mut recv,
            local_id,
            &self.limits,
            |network| known.get(&network).cloned(),
        )
        .await
        .map_err(|err| match err {
            ProtocolError::UnknownNetwork => {
                TransportError::Other("network is not active for the data plane".into())
            }
            other => TransportError::Other(other.to_string()),
        })?;

        let open: DataOpen = decode(
            &read_frame(&mut recv, self.limits.max_frame_len)
                .await
                .map_err(|err| TransportError::Other(err.to_string()))?,
        )
        .map_err(|err| TransportError::Other(err.to_string()))?;

        if open.protocol.is_empty() || open.protocol.len() > MAX_DATA_PROTOCOL_LEN {
            return Err(TransportError::Other(
                "data channel protocol id is out of bounds".into(),
            ));
        }

        let serves = self.lookup.serves(outcome.network_id, &open.protocol).await;
        if open.max_datagram == 0 || conn.max_datagram_size().is_none() {
            return Err(TransportError::Other(
                "data channel has no datagram support".into(),
            ));
        }
        let ack = DataOpenAck {
            accepted: serves,
            max_datagram: MAX_DATA_DATAGRAM as u32,
        };
        write_frame(
            &mut send,
            &encode(&ack).map_err(|err| TransportError::Other(err.to_string()))?,
            self.limits.max_frame_len,
        )
        .await
        .map_err(|err| TransportError::Other(err.to_string()))?;

        if !serves {
            conn.close(4u32.into(), b"no plugin for this protocol");
            return Err(TransportError::Declined(open.protocol));
        }

        let link = IrohLink::new(
            outcome.network_id,
            peer,
            conn,
            open.max_datagram as usize,
            send,
            recv,
        );
        Ok(InboundLink {
            network: outcome.network_id,
            peer,
            protocol: open.protocol,
            link: Arc::new(link),
        })
    }
}

impl PacketTransport for IrohTransport {
    fn name(&self) -> &str {
        "iroh"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn open<'a>(
        &'a self,
        network: NetworkId,
        peer: EndpointId,
        protocol: &'a str,
    ) -> BoxFuture<'a, Result<SharedLink, TransportError>> {
        Box::pin(async move {
            if protocol.is_empty() || protocol.len() > MAX_DATA_PROTOCOL_LEN {
                return Err(TransportError::Other(
                    "data channel protocol id is out of bounds".into(),
                ));
            }
            let keys = self
                .lookup
                .snapshot()
                .await
                .remove(&network)
                .ok_or_else(|| TransportError::Other("network is not active".into()))?;

            let addr = iroh::EndpointAddr::new(peer);
            let conn = self
                .adapter
                .endpoint()
                .connect(addr, DATA_ALPN)
                .await
                .map_err(|err| TransportError::Unreachable(err.to_string()))?;
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|err| TransportError::Unreachable(err.to_string()))?;

            handshake::initiate(
                &conn,
                &mut send,
                &mut recv,
                self.adapter.endpoint_id(),
                &keys,
                &self.limits,
            )
            .await
            .map_err(|err| TransportError::Other(err.to_string()))?;

            let open = DataOpen {
                protocol: protocol.to_string(),
                max_datagram: MAX_DATA_DATAGRAM as u32,
            };
            write_frame(
                &mut send,
                &encode(&open).map_err(|err| TransportError::Other(err.to_string()))?,
                self.limits.max_frame_len,
            )
            .await
            .map_err(|err| TransportError::Other(err.to_string()))?;

            let ack: DataOpenAck = decode(
                &read_frame(&mut recv, self.limits.max_frame_len)
                    .await
                    .map_err(|err| TransportError::Other(err.to_string()))?,
            )
            .map_err(|err| TransportError::Other(err.to_string()))?;

            if !ack.accepted {
                conn.close(4u32.into(), b"declined");
                return Err(TransportError::Declined(protocol.to_string()));
            }

            if ack.max_datagram == 0 || conn.max_datagram_size().is_none() {
                return Err(TransportError::Other(
                    "data channel has no datagram support".into(),
                ));
            }

            let link = IrohLink::new(network, peer, conn, ack.max_datagram as usize, send, recv);
            Ok(Arc::new(link) as SharedLink)
        })
    }
}
