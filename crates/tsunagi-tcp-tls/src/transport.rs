//! TCP TLS 1.3 transport implementation for Tsunagi.
//!
//! Provides [`TcpTlsTransport`] implementing [`PacketTransport`]
//! and [`TcpTlsLink`] implementing [`PacketLink`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use iroh::{EndpointId, Signature};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};
use tokio_rustls::TlsConnector;

use tsunagi::BoxFuture;
use tsunagi::dataplane::transport::{
    InboundLink, PacketLink, PacketTransport, SharedLink, TransportError,
};
use tsunagi::identity::{DeviceIdentity, NetworkId};

use crate::cert::{generate_self_signed_cert, make_client_config, make_server_config};

/// Default TCP port to bind and listen on.
pub const DEFAULT_PORT: u16 = 443;

/// Fallback port if 443 is unprivileged on Linux and denied.
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
    closed_notify: Arc<Notify>,
    is_closed: Arc<AtomicBool>,
    remote_addr: String,
}

impl TcpTlsLink {
    /// Creates a new `TcpTlsLink` from a stream that has already passed the TLS handshake.
    pub fn new<S>(network: NetworkId, peer: EndpointId, stream: S, remote_addr: String) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);

        let (tx_out, mut rx_out) = mpsc::channel::<Bytes>(256);
        let (tx_in, rx_in) = mpsc::channel::<Bytes>(256);

        let is_closed = Arc::new(AtomicBool::new(false));
        let closed_notify = Arc::new(Notify::new());

        let closed_flag_w = Arc::clone(&is_closed);
        let closed_notify_w = Arc::clone(&closed_notify);
        tokio::spawn(async move {
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
            closed_flag_w.store(true, Ordering::Release);
            closed_notify_w.notify_waiters();
        });

        let closed_flag_r = Arc::clone(&is_closed);
        let closed_notify_r = Arc::clone(&closed_notify);
        tokio::spawn(async move {
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
            closed_flag_r.store(true, Ordering::Release);
            closed_notify_r.notify_waiters();
        });

        Self {
            network,
            peer,
            tx: tx_out,
            rx: tokio::sync::Mutex::new(rx_in),
            closed_notify,
            is_closed,
            remote_addr,
        }
    }
}

impl PacketLink for TcpTlsLink {
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
        if self.is_closed.load(Ordering::Acquire) {
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
            if self.is_closed.load(Ordering::Acquire) {
                return;
            }
            self.closed_notify.notified().await;
        })
    }

    fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Acquire)
    }

    fn path_description(&self) -> String {
        format!("tcp-tls via {}", self.remote_addr)
    }
}

/// The `tcp-tls` packet transport.
pub struct TcpTlsTransport {
    identity: DeviceIdentity,
    local_id: EndpointId,
    listen_port: u16,
    sni: String,
    peer_addresses: std::sync::RwLock<HashMap<EndpointId, Vec<SocketAddr>>>,
    server_config: Arc<rustls::ServerConfig>,
    listener: Option<Arc<TcpListener>>,
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
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], target_port));

        let bind_result = {
            #[cfg(target_os = "linux")]
            let _guard = if target_port < 1024 {
                Some(NetBindServiceGuard::acquire())
            } else {
                None
            };

            std::net::TcpListener::bind(bind_addr)
        };

        let listener = match bind_result {
            Ok(std_listener) => {
                std_listener.set_nonblocking(true)?;
                let l = TcpListener::from_std(std_listener)?;
                tracing::info!(port = target_port, "TCP TLS listening");
                Some(Arc::new(l))
            }
            Err(err) if requested_port.is_none() => {
                let exe = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "tsunagi".into());

                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    tracing::warn!(
                        port = target_port,
                        %err,
                        "Cannot bind to default port {target_port} without privileges. \
                         To allow port 443 and TUN on Linux, grant capabilities once with:\n  \
                         sudo setcap cap_net_admin,cap_net_bind_service+p {exe}\n\
                         Falling back to port {FALLBACK_PORT}."
                    );
                } else {
                    tracing::warn!(
                        port = target_port,
                        %err,
                        "Cannot bind to default port {target_port}: {err}. \
                         Falling back to port {FALLBACK_PORT}."
                    );
                }

                let fallback_addr = SocketAddr::from(([0, 0, 0, 0], FALLBACK_PORT));
                match TcpListener::bind(fallback_addr).await {
                    Ok(l) => {
                        tracing::info!(port = FALLBACK_PORT, "TCP TLS listening on fallback port");
                        Some(Arc::new(l))
                    }
                    Err(fallback_err) => {
                        tracing::warn!(
                            port = FALLBACK_PORT,
                            err = %fallback_err,
                            "Cannot bind to fallback port {FALLBACK_PORT}: {fallback_err}. \
                             Falling back to ephemeral port."
                        );
                        let ephemeral_addr = SocketAddr::from(([0, 0, 0, 0], 0));
                        let l = TcpListener::bind(ephemeral_addr).await?;
                        let bound = l.local_addr()?.port();
                        tracing::info!(port = bound, "TCP TLS listening on ephemeral port");
                        Some(Arc::new(l))
                    }
                }
            }
            Err(err) => {
                let exe = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "tsunagi".into());
                tracing::warn!(
                    port = target_port,
                    %err,
                    "Cannot bind to requested port {target_port}: {err}. \
                     To allow port {target_port} and TUN on Linux, grant capabilities once with:\n  \
                     sudo setcap cap_net_admin,cap_net_bind_service+p {exe}"
                );
                return Err(Box::new(err));
            }
        };

        let bound_port = listener
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(target_port);

        Ok(Self {
            identity: identity.clone(),
            local_id: identity.endpoint_id(),
            listen_port: bound_port,
            sni,
            peer_addresses: std::sync::RwLock::new(HashMap::new()),
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
        if let Ok(mut guard) = self.peer_addresses.write() {
            let addrs = guard.entry(peer).or_default();
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        }
    }

    /// Runs the accept loop for inbound TCP TLS connections.
    pub async fn accept_loop<F>(&self, on_inbound: F)
    where
        F: Fn(InboundLink) + Send + Sync + Clone + 'static,
    {
        let Some(listener) = self.listener.as_ref().cloned() else {
            return;
        };

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&self.server_config));
        let local_id = self.local_id;

        while let Ok((socket, remote_addr)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let on_inbound = on_inbound.clone();

            tokio::spawn(async move {
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
            });
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

            let target_addrs = {
                let guard = self
                    .peer_addresses
                    .read()
                    .map_err(|_| TransportError::Other("lock poisoned".into()))?;
                guard.get(&peer).cloned().unwrap_or_default()
            };

            if target_addrs.is_empty() {
                return Err(TransportError::Unreachable(
                    "no known TCP address for peer".into(),
                ));
            }

            let mut connected_socket = None;
            let mut connected_addr = None;
            for addr in &target_addrs {
                if addr.ip().is_loopback() && addr.port() == self.listen_port {
                    continue;
                }
                match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(*addr)).await
                {
                    Ok(Ok(socket)) => {
                        connected_socket = Some(socket);
                        connected_addr = Some(*addr);
                        break;
                    }
                    _ => continue,
                }
            }

            let (socket, addr) = match (connected_socket, connected_addr) {
                (Some(s), Some(a)) => (s, a),
                _ => {
                    return Err(TransportError::Unreachable(
                        "cannot connect to any TCP address for peer".into(),
                    ));
                }
            };

            let client_config =
                make_client_config(peer).map_err(|err| TransportError::Other(err.to_string()))?;
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
    }
}
