//! Embedded peer-only TCP profiles. Control is supplied by the running mesh agent.
mod profile;
mod stream;
use iroh::EndpointId;
use profile::{Pair, rejected};
pub use profile::{Profile, Profiles, Ticket};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};
pub use stream::driven;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, oneshot},
    task::JoinSet,
    time::timeout,
};
use tsunagi::{
    BoxFuture, NetworkId,
    dataplane::transport::{
        ControlSender, InboundLink, PacketTransport, SharedLink, TransportError, TransportPayload,
    },
};
use tsunagi_tcp_tls::{
    candidates::{TcpEndpoint, dial_candidates},
    transport::TcpTlsLink,
};

/// A negotiated byte stream carrying length-prefixed mesh datagrams.
pub trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ByteStream for T {}
/// Owned stream returned by either side.
pub type Stream = Box<dyn ByteStream>;
/// A wire profile knows its own handshake and bytes, independent of reachability.
pub trait ShoesWire: Send + Sync + 'static {
    /// Stable protocol identifier.
    fn name(&self) -> &'static str;
    /// Version compared between peers.
    fn version(&self) -> u16;
    /// Perform the client handshake.
    fn connect<'a>(
        &'a self,
        tcp: TcpStream,
        peer: EndpointId,
        profile: &'a Profile,
    ) -> BoxFuture<'a, io::Result<Stream>>;
    /// Authenticate and consume an authorized incoming attempt.
    fn accept<'a>(
        &'a self,
        tcp: TcpStream,
        profiles: &'a Profiles,
    ) -> BoxFuture<'a, io::Result<(Ticket, Stream)>>;
}

/// A listening TCP carrier with private one-time, per-pair credentials.
pub struct ShoesTransport {
    wire: Arc<dyn ShoesWire>,
    listener: TcpListener,
    port: u16,
    profiles: Profiles,
    control: OnceLock<Arc<dyn ControlSender>>,
    replies: Arc<Semaphore>,
}
impl std::fmt::Debug for ShoesTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShoesTransport")
            .field("name", &self.name())
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}
impl ShoesTransport {
    /// An explicitly requested port must bind; an occupied default can use a dynamic port.
    pub async fn bind(
        wire: Arc<dyn ShoesWire>,
        port: Option<u16>,
        default_port: u16,
    ) -> io::Result<Arc<Self>> {
        let listener = match tsunagi_tcp_tls::candidates::listen(port.unwrap_or(default_port)) {
            Ok(l) => l,
            Err(e) if port.is_none() && e.kind() == io::ErrorKind::AddrInUse => {
                tsunagi_tcp_tls::candidates::listen(0)?
            }
            Err(e) => return Err(e),
        };
        let port = listener.local_addr()?.port();
        Ok(Arc::new(Self {
            wire,
            listener,
            port,
            profiles: Default::default(),
            control: OnceLock::new(),
            replies: Arc::new(Semaphore::new(64)),
        }))
    }

    /// Drives incoming sockets and their installation, bounded by one task set.
    pub async fn listen(self: Arc<Self>, agent: tsunagi::Agent) {
        let mut tasks = JoinSet::new();
        let mut expire = tokio::time::interval(profile::LIFETIME);
        loop {
            tokio::select! {
                _ = expire.tick() => self.profiles.expire(),
                _ = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = self.listener.accept(), if tasks.len() < 64 => {
                    let Ok((tcp, address)) = accepted else { break; };
                    let owner = self.clone();
                    let agent = agent.clone();
                    tasks.spawn(async move {
                        let _ = tcp.set_nodelay(true);
                        if let Ok(Ok((ticket, stream))) = timeout(Duration::from_secs(8), owner.wire.accept(tcp, &owner.profiles)).await {
                            let (network, peer) = ticket.pair;
                            let protocol = owner.wire.name();
                            let link = Arc::new(TcpTlsLink::framed(protocol, network, peer, stream, address.to_string()));
                            let _ = agent.install_inbound_link(InboundLink { network, peer, protocol: protocol.into(), link }).await;
                        }
                    });
                }
            }
        }
    }

    async fn authorize(&self, pair: Pair) -> Result<Profile, TransportError> {
        let control = self.control.get().ok_or(TransportError::Closed)?;
        let profile = Profile::fresh();
        let (tx, rx) = oneshot::channel();
        self.profiles
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(&pair)
            .ok_or(TransportError::Closed)?
            .waiting = Some((profile.tag, tx));
        // Fixed lengths distinguish an offer (tag + secret + variant) from its receipt (tag).
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&profile.tag);
        bytes.extend_from_slice(&profile.secret);
        bytes.push(u8::from(profile.variant));
        control
            .send(pair.0, pair.1, self.name(), TransportPayload::new(bytes))
            .await?;
        rx.await.map_err(|_| TransportError::Closed)?;
        Ok(profile)
    }
}
impl TcpEndpoint for ShoesTransport {
    fn wire_version(&self) -> u16 {
        self.wire.version()
    }
    fn bound_port(&self) -> u16 {
        self.port
    }
    fn set_pair_addresses(
        &self,
        network: NetworkId,
        peer: EndpointId,
        addresses: Option<Vec<SocketAddr>>,
    ) {
        let mut slots = self.profiles.0.lock().unwrap_or_else(|p| p.into_inner());
        match addresses {
            Some(addresses) => slots.entry((network, peer)).or_default().addresses = addresses,
            None => {
                slots.remove(&(network, peer));
            }
        }
    }
    fn clear_network(&self, network: NetworkId) {
        self.profiles
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|(n, _), _| *n != network);
    }
}
impl PacketTransport for ShoesTransport {
    fn name(&self) -> &str {
        self.wire.name()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn attach_control(&self, control: Arc<dyn ControlSender>) {
        let _ = self.control.set(control);
    }
    fn on_control(
        &self,
        network: NetworkId,
        peer: EndpointId,
        protocol: &str,
        bytes: &[u8],
    ) -> Result<(), TransportError> {
        let bad = || TransportError::Declined("invalid Shoes negotiation".into());
        if protocol != self.name() {
            return Err(bad());
        }
        let pair = (network, peer);
        let tag: [u8; 32] = bytes
            .get(..32)
            .ok_or_else(bad)?
            .try_into()
            .map_err(|_| bad())?;
        match bytes.len() {
            32 => {
                let mut slots = self.profiles.0.lock().unwrap_or_else(|p| p.into_inner());
                let slot = slots.get_mut(&pair).ok_or_else(bad)?;
                let (_, ack) = slot.waiting.take_if(|(id, _)| *id == tag).ok_or_else(bad)?;
                let _ = ack.send(());
            }
            65 if bytes[64] <= 1 => {
                let secret = bytes[32..64].try_into().map_err(|_| bad())?;
                let permit = self
                    .replies
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| bad())?;
                let sender = self.control.get().ok_or_else(bad)?.clone();
                let name = self.wire.name();
                self.profiles
                    .offer(
                        pair,
                        Profile {
                            tag,
                            secret,
                            variant: bytes[64] == 1,
                        },
                    )
                    .map_err(|_| bad())?;
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = timeout(
                        Duration::from_secs(4),
                        sender.send(network, peer, name, TransportPayload::new(tag.to_vec())),
                    )
                    .await;
                });
            }
            _ => return Err(bad()),
        }
        Ok(())
    }
    fn open<'a>(
        &'a self,
        network: NetworkId,
        peer: EndpointId,
        protocol: &'a str,
    ) -> BoxFuture<'a, Result<SharedLink, TransportError>> {
        Box::pin(async move {
            if protocol != self.name() {
                return Err(TransportError::Declined(protocol.into()));
            }
            let pair = (network, peer);
            let addresses = self
                .profiles
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&pair)
                .map(|s| s.addresses.clone())
                .ok_or_else(|| TransportError::Unreachable(rejected().to_string()))?;
            dial_candidates(addresses, |tcp, addr| async move {
                let profile = self.authorize(pair).await?;
                let stream = self
                    .wire
                    .connect(tcp, peer, &profile)
                    .await
                    .map_err(|_| TransportError::Declined("Shoes handshake failed".into()))?;
                Ok(Arc::new(TcpTlsLink::framed(
                    self.wire.name(),
                    network,
                    peer,
                    stream,
                    addr.to_string(),
                )) as SharedLink)
            })
            .await
        })
    }
}
