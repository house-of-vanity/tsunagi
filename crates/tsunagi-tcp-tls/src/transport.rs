//! TCP TLS 1.3 transport implementation for Tsunagi.
//!
//! Provides [`TcpTlsTransport`] implementing [`PacketTransport`]
//! and [`TcpTlsLink`] implementing [`PacketLink`].

use crate::candidates::{Candidates, TcpEndpoint, dial_candidates};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use iroh::{EndpointId, Signature};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio_rustls::TlsConnector;

use tsunagi::BoxFuture;
use tsunagi::dataplane::transport::{
    InboundLink, PacketLink, PacketTransport, SharedLink, TransportError,
};
use tsunagi::identity::{DeviceIdentity, NetworkId};

use crate::cert::{generate_self_signed_cert, make_client_config, make_server_config};

/// Default TCP port to bind and listen on.
pub const DEFAULT_PORT: u16 = 9442;

/// Second unprivileged port when the preferred listener cannot bind.
pub const FALLBACK_PORT: u16 = 8443;

/// Maximum payload length for a single framed datagram over TLS.
pub const MAX_FRAME_SIZE: usize = 65535;

/// Initial handshake message on established TLS stream (128 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkHandshake {
    /// The overlay network ID.
    pub network: NetworkId,
    /// The connecting client's endpoint ID.
    pub client_id: EndpointId,
    /// Ed25519 signature over `tsunagi-tcp-tls-link-v1` + network + server ID.
    pub signature: [u8; 64],
}

impl LinkHandshake {
    /// Total encoded length in bytes.
    pub const LEN: usize = 32 + 32 + 64; // 128

    /// Serializes to fixed-size byte array.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut buf = [0u8; Self::LEN];
        buf[0..32].copy_from_slice(self.network.as_bytes());
        buf[32..64].copy_from_slice(self.client_id.as_bytes());
        buf[64..128].copy_from_slice(&self.signature);
        buf
    }

    /// Deserializes from byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::LEN {
            return None;
        }
        let network = NetworkId::from_bytes(bytes[0..32].try_into().ok()?);
        let client_id = EndpointId::from_bytes(bytes[32..64].try_into().ok()?).ok()?;
        let signature: [u8; 64] = bytes[64..128].try_into().ok()?;
        Some(Self {
            network,
            client_id,
            signature,
        })
    }
}

/// Acknowledgement message on established TLS stream (1 byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkAck {
    /// Whether the link was accepted by the server.
    pub accepted: bool,
}

impl LinkAck {
    /// Total encoded length in bytes.
    pub const LEN: usize = 1;

    /// Serializes to fixed-size byte array.
    pub fn to_bytes(&self) -> [u8; 1] {
        [if self.accepted { 1 } else { 0 }]
    }

    /// Deserializes from byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 1 {
            return None;
        }
        Some(Self {
            accepted: bytes[0] == 1,
        })
    }
}

fn link_handshake_bytes(network: NetworkId, server_id: EndpointId) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(23 + 32 + 32);
    bytes.extend_from_slice(b"tsunagi-tcp-tls-link-v1");
    bytes.extend_from_slice(network.as_bytes());
    bytes.extend_from_slice(server_id.as_bytes());
    bytes
}

/// An authenticated datagram link carried over a TCP TLS 1.3 stream.
#[derive(Debug)]
pub struct TcpTlsLink {
    network: NetworkId,
    peer: EndpointId,
    tx: mpsc::Sender<Bytes>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    tasks: [tokio::task::AbortHandle; 2],
    closed: watch::Sender<bool>,
    remote_addr: String,
    protocol: &'static str,
}

impl TcpTlsLink {
    /// Creates a new `TcpTlsLink` from a stream that has already passed the TLS handshake.
    pub fn new<S>(network: NetworkId, peer: EndpointId, stream: S, remote_addr: String) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        Self::framed("tcp-tls", network, peer, stream, remote_addr)
    }
    /// Frames opaque mesh datagrams on a mutually authenticated carrier stream.
    pub fn framed<S>(
        protocol: &'static str,
        network: NetworkId,
        peer: EndpointId,
        stream: S,
        remote_addr: String,
    ) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);

        let (tx_out, mut rx_out) = mpsc::channel::<Bytes>(256);
        let (tx_in, rx_in) = mpsc::channel::<Bytes>(256);

        let (closed, _) = watch::channel(false);
        let writer_closed = closed.clone();
        let writer_task = tokio::spawn(async move {
            while let Some(msg) = rx_out.recv().await {
                if msg.len() > MAX_FRAME_SIZE {
                    continue;
                }
                let len = msg.len() as u16;
                if writer.write_all(&len.to_be_bytes()).await.is_err() {
                    break;
                }
                if writer.write_all(&msg).await.is_err() {
                    break;
                }
                if writer.flush().await.is_err() {
                    break;
                }
            }
            writer_closed.send_replace(true);
        });

        let reader_closed = closed.clone();
        let reader_task = tokio::spawn(async move {
            let mut len_buf = [0u8; 2];
            loop {
                if reader.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                if len > MAX_FRAME_SIZE {
                    break;
                }
                let mut buf = vec![0u8; len];
                if reader.read_exact(&mut buf).await.is_err() {
                    break;
                }
                if tx_in.send(Bytes::from(buf)).await.is_err() {
                    break;
                }
            }
            reader_closed.send_replace(true);
        });

        Self {
            network,
            peer,
            tx: tx_out,
            rx: tokio::sync::Mutex::new(rx_in),
            tasks: [writer_task.abort_handle(), reader_task.abort_handle()],
            closed,
            remote_addr,
            protocol,
        }
    }
}

impl Drop for TcpTlsLink {
    fn drop(&mut self) {
        self.close();
    }
}
impl PacketLink for TcpTlsLink {
    fn close(&self) {
        self.closed.send_replace(true);
        for task in &self.tasks {
            task.abort();
        }
    }
    fn network(&self) -> NetworkId {
        self.network
    }

    fn peer(&self) -> EndpointId {
        self.peer
    }

    fn max_datagram_size(&self) -> usize {
        MAX_FRAME_SIZE
    }

    fn send(&self, payload: Bytes) -> Result<(), TransportError> {
        if payload.len() > MAX_FRAME_SIZE {
            return Err(TransportError::TooLarge {
                size: payload.len(),
                limit: MAX_FRAME_SIZE,
            });
        }
        if *self.closed.borrow() {
            return Err(TransportError::Closed);
        }
        self.tx
            .try_send(payload)
            .map_err(|_| TransportError::Closed)
    }

    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async move {
            let mut guard = self.rx.lock().await;
            guard.recv().await
        })
    }

    fn closed(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let _ = self.closed.subscribe().wait_for(|closed| *closed).await;
        })
    }

    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    fn path_description(&self) -> String {
        format!("{} via {}", self.protocol, self.remote_addr)
    }
}

/// The `tcp-tls` packet transport.
pub struct TcpTlsTransport {
    identity: DeviceIdentity,
    local_id: EndpointId,
    listen_port: u16,
    sni: String,
    peer_addresses: Candidates,
    server_config: Arc<rustls::ServerConfig>,
    listener: TcpListener,
}

impl std::fmt::Debug for TcpTlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTlsTransport")
            .field("local_id", &self.local_id.fmt_short().to_string())
            .field("listen_port", &self.listen_port)
            .field("sni", &self.sni)
            .finish()
    }
}

#[cfg(target_os = "linux")]
struct NetBindServiceGuard {
    raised: bool,
}

#[cfg(target_os = "linux")]
impl NetBindServiceGuard {
    fn acquire() -> Self {
        let already = caps::has_cap(
            None,
            caps::CapSet::Effective,
            caps::Capability::CAP_NET_BIND_SERVICE,
        )
        .unwrap_or(false);

        if already {
            return Self { raised: false };
        }

        let permitted = caps::has_cap(
            None,
            caps::CapSet::Permitted,
            caps::Capability::CAP_NET_BIND_SERVICE,
        )
        .unwrap_or(false);

        if permitted
            && caps::raise(
                None,
                caps::CapSet::Effective,
                caps::Capability::CAP_NET_BIND_SERVICE,
            )
            .is_ok()
        {
            Self { raised: true }
        } else {
            Self { raised: false }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetBindServiceGuard {
    fn drop(&mut self) {
        if self.raised {
            let _ = caps::drop(
                None,
                caps::CapSet::Effective,
                caps::Capability::CAP_NET_BIND_SERVICE,
            );
        }
    }
}

impl TcpTlsTransport {
    /// Binds a new TCP TLS transport using the device identity, configured port, and SNI domain.
    pub async fn bind(
        identity: &DeviceIdentity,
        requested_port: Option<u16>,
        requested_sni: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let sni = requested_sni
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| crate::cert::DEFAULT_SNI.to_string());
        let (cert, key) = generate_self_signed_cert(&identity.secret_bytes(), &sni)?;
        let server_config = make_server_config(cert, key)?;

        let target_port = requested_port.unwrap_or(DEFAULT_PORT);

        let bind_result = {
            #[cfg(target_os = "linux")]
            let _guard = if target_port < 1024 {
                Some(NetBindServiceGuard::acquire())
            } else {
                None
            };

            crate::candidates::listen(target_port)
        };

        let listener = match bind_result {
            Ok(listener) => listener,
            Err(err) if requested_port.is_none() => {
                tracing::warn!(port = target_port, %err, "TCP TLS default port unavailable");
                crate::candidates::listen(FALLBACK_PORT).or_else(|err| {
                    tracing::warn!(port = FALLBACK_PORT, %err, "TCP TLS fallback port unavailable");
                    crate::candidates::listen(0)
                })?
            }
            Err(err) => {
                tracing::warn!(port = target_port, %err, "Cannot bind requested TCP TLS port");
                return Err(Box::new(err));
            }
        };
        let bound_port = listener.local_addr()?.port();
        tracing::info!(port = bound_port, "TCP TLS listening");

        Ok(Self {
            identity: identity.clone(),
            local_id: identity.endpoint_id(),
            listen_port: bound_port,
            sni,
            peer_addresses: Candidates::default(),
            server_config,
            listener,
        })
    }

    /// The port this transport is listening on.
    pub fn bound_port(&self) -> u16 {
        self.listen_port
    }

    /// The SNI domain this transport advertises during TLS handshake.
    pub fn sni(&self) -> &str {
        &self.sni
    }

    /// Records an observed TCP target address for a peer.
    pub fn set_peer_addr(&self, peer: EndpointId, addr: SocketAddr) {
        if let Ok(mut guard) = self.peer_addresses.manual.lock() {
            let addrs = guard.entry(peer).or_default();
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }
    }

    /// Replaces a bounded candidate set learned through an authenticated session.
    pub fn replace_peer_addrs(&self, peer: EndpointId, addresses: Vec<SocketAddr>) {
        if let Ok(mut peers) = self.peer_addresses.manual.lock() {
            if addresses.is_empty() {
                peers.remove(&peer);
            } else {
                peers.insert(peer, addresses.into_iter().take(32).collect());
            }
        }
    }

    /// Runs the accept loop for inbound TCP TLS connections.
    pub async fn accept_loop<F>(&self, on_inbound: F)
    where
        F: Fn(InboundLink) + Send + Sync + Clone + 'static,
    {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&self.server_config));
        let local_id = self.local_id;

        let mut handshakes = tokio::task::JoinSet::new();
        loop {
            let accepted = tokio::select! {
                _ = handshakes.join_next(), if !handshakes.is_empty() => continue,
                result = self.listener.accept(), if handshakes.len() < 64 => result,
            };
            let Ok((socket, remote_addr)) = accepted else {
                break;
            };
            let _ = socket.set_nodelay(true);
            let acceptor = acceptor.clone();
            let on_inbound = on_inbound.clone();
            handshakes.spawn(tokio::time::timeout(Duration::from_secs(8), async move {
                let mut tls_stream = match acceptor.accept(socket).await {
                    Ok(s) => s,
                    Err(err) => {
                        tracing::debug!(%err, "inbound TLS handshake failed");
                        return;
                    }
                };

                let mut hello_buf = [0u8; LinkHandshake::LEN];
                if tls_stream.read_exact(&mut hello_buf).await.is_err() {
                    return;
                }
                let Some(hello) = LinkHandshake::from_bytes(&hello_buf) else {
                    return;
                };

                let msg = link_handshake_bytes(hello.network, local_id);
                let sig = Signature::from_bytes(&hello.signature);
                if hello.client_id.verify(&msg, &sig).is_err() {
                    tracing::debug!("LinkHandshake signature verification failed");
                    return;
                }

                let ack = LinkAck { accepted: true };
                let ack_bytes = ack.to_bytes();
                if tls_stream.write_all(&ack_bytes).await.is_err() {
                    return;
                }
                if tls_stream.flush().await.is_err() {
                    return;
                }

                let link = TcpTlsLink::new(
                    hello.network,
                    hello.client_id,
                    tls_stream,
                    remote_addr.to_string(),
                );
                on_inbound(InboundLink {
                    network: hello.network,
                    peer: hello.client_id,
                    protocol: "tcp-tls".into(),
                    link: Arc::new(link),
                });
            }));
        }
    }
}

impl PacketTransport for TcpTlsTransport {
    fn name(&self) -> &str {
        "tcp-tls"
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
            if protocol != "tcp-tls" {
                return Err(TransportError::Declined(protocol.to_string()));
            }

            let addresses = self
                .peer_addresses
                .pairs
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&(network, peer))
                .cloned()
                .unwrap_or_else(|| {
                    self.peer_addresses
                        .manual
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .get(&peer)
                        .cloned()
                        .unwrap_or_default()
                });
            dial_candidates(addresses, |socket, addr| async move {
                let client_config = make_client_config(peer)
                    .map_err(|err| TransportError::Other(err.to_string()))?;
                let connector = TlsConnector::from(client_config);

                let server_name = rustls::pki_types::ServerName::try_from(self.sni.as_str())
                    .map_err(|err| TransportError::Other(err.to_string()))?
                    .to_owned();

                let mut tls_stream = connector
                    .connect(server_name, socket)
                    .await
                    .map_err(|err| TransportError::Other(format!("TLS handshake failed: {err}")))?;

                // Send LinkHandshake (fixed 128 bytes)
                let msg = link_handshake_bytes(network, peer);
                let sig = self.identity.sign(&msg);
                let hello = LinkHandshake {
                    network,
                    client_id: self.local_id,
                    signature: sig.to_bytes(),
                };
                let hello_bytes = hello.to_bytes();
                tls_stream
                    .write_all(&hello_bytes)
                    .await
                    .map_err(|err| TransportError::Other(err.to_string()))?;
                tls_stream
                    .flush()
                    .await
                    .map_err(|err| TransportError::Other(err.to_string()))?;

                // Read LinkAck (fixed 1 byte)
                let mut ack_buf = [0u8; LinkAck::LEN];
                tls_stream
                    .read_exact(&mut ack_buf)
                    .await
                    .map_err(|err| TransportError::Other(err.to_string()))?;
                let ack = LinkAck::from_bytes(&ack_buf)
                    .ok_or_else(|| TransportError::Other("invalid link ack".into()))?;

                if !ack.accepted {
                    return Err(TransportError::Declined("link declined".into()));
                }

                let link = TcpTlsLink::new(network, peer, tls_stream, addr.to_string());
                Ok(Arc::new(link) as SharedLink)
            })
            .await
        })
    }
}

impl TcpEndpoint for TcpTlsTransport {
    fn wire_version(&self) -> u16 {
        crate::TCP_TLS_VERSION
    }
    fn bound_port(&self) -> u16 {
        self.listen_port
    }
    fn set_pair_addresses(
        &self,
        network: NetworkId,
        peer: EndpointId,
        addresses: Option<Vec<SocketAddr>>,
    ) {
        let mut pairs = self
            .peer_addresses
            .pairs
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match addresses {
            Some(addresses) => {
                pairs.insert((network, peer), addresses);
            }
            None => {
                pairs.remove(&(network, peer));
            }
        }
    }
    fn clear_network(&self, network: NetworkId) {
        self.peer_addresses
            .pairs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|(n, _), _| *n != network);
    }
}
