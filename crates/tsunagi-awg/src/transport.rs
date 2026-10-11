//! Private pair negotiation. No secret profiles in capabilities or durable state.
use crate::{
    AWG_PROTOCOL, AWG_WIRE_VERSION,
    profile::PairProfile,
    session::{self, PairLink},
};
use boringtun::{
    noise::Tunn,
    x25519::{PublicKey, StaticSecret},
};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tsunagi::dataplane::transport::TransportPayload;
use tsunagi::dataplane::transport::{
    ControlSender, InboundLink, PacketLink, PacketTransport, SharedLink, TransportError,
};
use tsunagi::{BoxFuture, NetworkId};

type Pair = (NetworkId, EndpointId);
#[derive(Serialize, Deserialize)]
enum Negotiation {
    Offer {
        version: u16,
        profile: PairProfile,
        key: [u8; 32],
        #[serde(deserialize_with = "bounded_addresses")]
        addresses: Vec<SocketAddr>,
    },
    Answer {
        attempt: [u8; 16],
        key: [u8; 32],
        #[serde(deserialize_with = "bounded_addresses")]
        addresses: Vec<SocketAddr>,
    },
}
fn bounded_addresses<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<SocketAddr>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<SocketAddr>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most 32 UDP candidates")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|n| n > 32) {
                return Err(serde::de::Error::custom("too many UDP candidates"));
            }
            let mut addresses = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(32));
            while let Some(address) = sequence.next_element()? {
                if addresses.len() == 32 {
                    return Err(serde::de::Error::custom("too many UDP candidates"));
                }
                addresses.push(address);
            }
            Ok(addresses)
        }
    }
    deserializer.deserialize_seq(Visitor)
}
struct Pending {
    profile: PairProfile,
    key: StaticSecret,
    socket: UdpSocket,
    reply: oneshot::Sender<Result<SharedLink, TransportError>>,
}
struct Inner {
    stopped: watch::Sender<bool>,
    local: EndpointId,
    bind: Ipv4Addr,
    stun: Option<String>,
    busy: Mutex<HashSet<Pair>>,
    control: OnceLock<Arc<dyn ControlSender>>,
    allowed: Mutex<HashSet<Pair>>,
    pending: Mutex<HashMap<Pair, Pending>>,
    links: Mutex<HashMap<Pair, Arc<PairLink>>>,
    inbound: mpsc::Sender<InboundLink>,
    port_by_pair: Mutex<HashMap<Pair, u16>>,
}
/// Public diagnostics for one pair. No key or masking parameters are exposed.
#[derive(Debug, Clone)]
pub struct PairOverview {
    /// Other endpoint's authenticated identity.
    pub peer: EndpointId,
    /// Fresh connection-attempt identifier.
    pub attempt: [u8; 16],
    /// Last known UDP port; None if diagnostics race with pair retirement.
    pub local_port: Option<u16>,
    /// Actual transport path, if established.
    pub path: String,
    /// Whether this attempt has been retired.
    pub closed: bool,
}
/// A bounded set of independently configured pair engines.
pub struct AwgTransport {
    inner: Arc<Inner>,
    commands: mpsc::Sender<(NetworkId, EndpointId, Negotiation)>,
    incoming: tokio::sync::Mutex<mpsc::Receiver<InboundLink>>,
}
impl std::fmt::Debug for AwgTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwgTransport")
            .field("local", &self.inner.local)
            .finish_non_exhaustive()
    }
}
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}
fn error(text: &str) -> TransportError {
    TransportError::Other(text.into())
}
async fn addresses(inner: &Inner, socket: &UdpSocket) -> Result<Vec<SocketAddr>, TransportError> {
    let local = socket
        .local_addr()
        .map_err(|_| error("AWG socket address unavailable"))?;
    let mut candidates = if inner.bind.is_loopback() {
        vec![local]
    } else {
        tsunagi_wireguard::local_ip_candidates()
            .into_iter()
            .filter(|ip| ip.is_ipv4())
            .take(31)
            .map(|ip| SocketAddr::new(ip, local.port()))
            .collect()
    };
    if let Some(server) = &inner.stun
        && let Some(mapped) = crate::stun::mapped(socket, server).await
        && !candidates.contains(&mapped)
    {
        candidates.push(mapped);
    }
    if candidates.is_empty() {
        return Err(error("AWG has no UDP address candidates"));
    }
    Ok(candidates)
}
fn validate_endpoint(key: &[u8; 32], addresses: &[SocketAddr]) -> Result<(), TransportError> {
    if *key == [0; 32]
        || addresses.is_empty()
        || addresses.len() > 32
        || addresses.iter().any(|address| {
            address.port() == 0
                || !address.is_ipv4()
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
                || matches!(address.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
        })
    {
        return Err(error("invalid AWG endpoint"));
    }
    Ok(())
}

impl AwgTransport {
    /// Starts the coordinator. Production binds wildcard IPv4; tests use loopback.
    pub fn new(local: EndpointId, bind: Ipv4Addr) -> Arc<Self> {
        Self::new_with_stun(local, bind, None)
    }
    /// Enables an optional STUN server (host:port) for this pair's own socket.
    /// Local-only callers pass None; failure still permits local UDP candidates.
    pub fn new_with_stun(local: EndpointId, bind: Ipv4Addr, stun: Option<String>) -> Arc<Self> {
        let (commands, mut rx) = mpsc::channel(64);
        let (inbound, incoming) = mpsc::channel(64);
        let (stopped, _) = watch::channel(false);
        let inner = Arc::new(Inner {
            stopped,
            local,
            bind,
            stun,
            busy: Mutex::default(),
            control: OnceLock::new(),
            allowed: Mutex::default(),
            pending: Mutex::default(),
            links: Mutex::default(),
            inbound,
            port_by_pair: Mutex::default(),
        });
        let weak = Arc::downgrade(&inner);
        let mut stopped = inner.stopped.subscribe();
        tokio::spawn(async move {
            while let Some((network, peer, message)) =
                tokio::select! { biased; _=stopped.changed()=>None, message=rx.recv()=>message }
            {
                let Some(inner) = weak.upgrade() else {
                    break;
                };
                if !lock(&inner.allowed).contains(&(network, peer))
                    || !lock(&inner.busy).insert((network, peer))
                {
                    continue;
                }
                tokio::spawn(async move {
                    let mut stop = inner.stopped.subscribe();
                    tokio::select! {biased; _=stop.changed()=>{}, _=async {
                        if let Err(err)=receive(&inner,(network,peer),message).await {tracing::debug!(%err,"AWG pair negotiation rejected");}
                    }=>{}}
                    lock(&inner.busy).remove(&(network, peer));
                });
            }
        });
        Arc::new(Self {
            inner,
            commands,
            incoming: tokio::sync::Mutex::new(incoming),
        })
    }
    /// Registers a peer after its authenticated capability has been validated.
    pub fn allow_peer(&self, network: NetworkId, peer: EndpointId) {
        let mut allowed = lock(&self.inner.allowed);
        if !*self.inner.stopped.borrow() && allowed.len() < 128 {
            allowed.insert((network, peer));
        }
    }
    /// Retires a pair when its network membership session goes away.
    pub fn forget_peer(&self, network: NetworkId, peer: EndpointId) {
        let pair = (network, peer);
        lock(&self.inner.allowed).remove(&pair);
        lock(&self.inner.pending).remove(&pair);
        lock(&self.inner.port_by_pair).remove(&pair);
        if let Some(link) = lock(&self.inner.links).remove(&pair) {
            link.close();
        }
    }
    /// Stops all pair engines in this network.
    pub fn stop_network(&self, network: NetworkId) {
        let peers: Vec<_> = lock(&self.inner.allowed)
            .iter()
            .filter(|(n, _)| *n == network)
            .map(|(_, p)| *p)
            .collect();
        for peer in peers {
            self.forget_peer(network, peer);
        }
    }
    /// Stops all sockets and coordinator work without waiting for remote peers.
    pub fn shutdown(&self) {
        self.inner.stopped.send_replace(true);
        lock(&self.inner.allowed).clear();
        lock(&self.inner.pending).clear();
        for (_, link) in lock(&self.inner.links).drain() {
            link.close();
        }
        lock(&self.inner.port_by_pair).clear();
    }
    /// Receives a successfully negotiated and authenticated inbound pair link.
    pub async fn next_inbound(&self) -> Option<InboundLink> {
        let mut stopped = self.inner.stopped.subscribe();
        if *stopped.borrow() {
            return None;
        }
        let mut incoming = self.incoming.lock().await;
        tokio::select! {biased; _=stopped.changed()=>None, link=incoming.recv()=>link}
    }
    /// Takes a public snapshot of this network's pair attempts.
    pub fn overview(&self, network: NetworkId) -> Vec<PairOverview> {
        let links = lock(&self.inner.links);
        let ports = lock(&self.inner.port_by_pair);
        links
            .iter()
            .filter(|((n, _), _)| *n == network)
            .map(|((_, peer), link)| PairOverview {
                peer: *peer,
                attempt: link.attempt,
                local_port: ports.get(&(network, *peer)).copied(),
                path: link.path_description(),
                closed: link.is_closed(),
            })
            .collect()
    }
}
impl PacketTransport for AwgTransport {
    fn name(&self) -> &str {
        AWG_PROTOCOL
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn attach_control(&self, control: Arc<dyn ControlSender>) {
        let _ = self.inner.control.set(control);
    }
    fn on_control(
        &self,
        network: NetworkId,
        peer: EndpointId,
        protocol: &str,
        payload: &[u8],
    ) -> Result<(), TransportError> {
        if protocol != AWG_PROTOCOL || !lock(&self.inner.allowed).contains(&(network, peer)) {
            return Err(TransportError::Declined(protocol.into()));
        }
        if payload.len() > 4096 {
            return Err(error("AWG negotiation too large"));
        }
        let message: Negotiation =
            postcard::from_bytes(payload).map_err(|_| error("malformed AWG negotiation"))?;
        match &message {
            Negotiation::Offer {
                version,
                profile,
                key,
                addresses,
            } => {
                if *version != AWG_WIRE_VERSION || peer.as_bytes() >= self.inner.local.as_bytes() {
                    return Err(error("invalid AWG offer role/version"));
                }
                profile.validate().map_err(error)?;
                validate_endpoint(key, addresses)?;
            }
            Negotiation::Answer { key, addresses, .. } => validate_endpoint(key, addresses)?,
        }
        self.commands
            .try_send((network, peer, message))
            .map_err(|_| error("AWG negotiation queue full"))
    }
    fn open<'a>(
        &'a self,
        network: NetworkId,
        peer: EndpointId,
        protocol: &'a str,
    ) -> BoxFuture<'a, Result<SharedLink, TransportError>> {
        Box::pin(async move {
            let pair = (network, peer);
            if protocol != AWG_PROTOCOL
                || self.inner.local.as_bytes() >= peer.as_bytes()
                || !lock(&self.inner.allowed).contains(&pair)
            {
                return Err(TransportError::Declined(protocol.into()));
            }
            let control = self
                .inner
                .control
                .get()
                .ok_or_else(|| error("AWG control plane unavailable"))?;
            let socket = UdpSocket::bind((self.inner.bind, 0))
                .await
                .map_err(|_| error("AWG UDP bind failed"))?;
            let profile = PairProfile::generate();
            let attempt = profile.id();
            let key = StaticSecret::from(rand::random::<[u8; 32]>());
            let public = PublicKey::from(&key).to_bytes();
            let message = Negotiation::Offer {
                version: AWG_WIRE_VERSION,
                profile: profile.clone(),
                key: public,
                addresses: addresses(&self.inner, &socket).await?,
            };
            let (reply, rx) = oneshot::channel();
            if lock(&self.inner.pending).len() >= 128 {
                return Err(error("too many AWG pair negotiations"));
            }
            lock(&self.inner.pending).insert(
                pair,
                Pending {
                    profile,
                    key,
                    socket,
                    reply,
                },
            );
            // A cancellation guard also retires partially started attempts.
            let mut guard = AttemptGuard {
                inner: Arc::downgrade(&self.inner),
                pair,
                attempt,
                completed: false,
            };
            let bytes =
                postcard::to_stdvec(&message).map_err(|_| error("AWG offer encoding failed"))?;
            control
                .send(network, peer, AWG_PROTOCOL, TransportPayload::new(bytes))
                .await?;
            let result = tokio::time::timeout(Duration::from_secs(15), rx)
                .await
                .map_err(|_| error("AWG negotiation/handshake timed out"))?
                .map_err(|_| error("AWG attempt cancelled"))?;
            guard.completed = result.is_ok();
            result
        })
    }
}
struct AttemptGuard {
    inner: Weak<Inner>,
    pair: Pair,
    attempt: [u8; 16],
    completed: bool,
}
impl Drop for AttemptGuard {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            let mut pending = lock(&inner.pending);
            if pending
                .get(&self.pair)
                .is_some_and(|p| p.profile.id() == self.attempt)
            {
                pending.remove(&self.pair);
            }
            drop(pending);
            if !self.completed
                && let Some(link) = lock(&inner.links).get(&self.pair)
                && link.attempt == self.attempt
            {
                link.close();
            }
        }
    }
}
async fn receive(
    inner: &Arc<Inner>,
    pair: Pair,
    message: Negotiation,
) -> Result<(), TransportError> {
    if !lock(&inner.allowed).contains(&pair) {
        return Err(error("AWG peer no longer authenticated"));
    }
    match message {
        Negotiation::Offer {
            profile,
            key,
            addresses: candidates,
            ..
        } => {
            if let Some(link) = lock(&inner.links).get(&pair) {
                if link.attempt == profile.id() {
                    return Err(error("duplicate AWG offer"));
                }
                link.close();
            }
            let socket = UdpSocket::bind((inner.bind, 0))
                .await
                .map_err(|_| error("AWG UDP bind failed"))?;
            let local_port = socket
                .local_addr()
                .map_err(|_| error("AWG socket address unavailable"))?
                .port();
            let local_key = StaticSecret::from(rand::random::<[u8; 32]>());
            let public = PublicKey::from(&local_key).to_bytes();
            let answer = Negotiation::Answer {
                attempt: profile.id(),
                key: public,
                addresses: addresses(inner, &socket).await?,
            };
            let tunn = Tunn::new(
                local_key,
                PublicKey::from(key),
                Some(profile.psk),
                Some(1),
                rand::random(),
                None,
            );

            let link = session::start(
                pair.0,
                pair.1,
                socket,
                tunn,
                profile,
                candidates,
                inner.stopped.subscribe(),
            );
            if !lock(&inner.allowed).contains(&pair) {
                link.close();
                return Err(error("AWG membership ended"));
            }
            lock(&inner.links).insert(pair, link.clone());
            lock(&inner.port_by_pair).insert(pair, local_port);
            let control = inner
                .control
                .get()
                .ok_or_else(|| error("AWG control unavailable"))?;
            if let Err(err) = control
                .send(
                    pair.0,
                    pair.1,
                    AWG_PROTOCOL,
                    TransportPayload::new(
                        postcard::to_stdvec(&answer)
                            .map_err(|_| error("AWG answer encoding failed"))?,
                    ),
                )
                .await
            {
                link.close();
                return Err(err);
            }
            publish_when_up(Arc::downgrade(inner), pair, link, None);
        }
        Negotiation::Answer {
            attempt,
            key,
            addresses: candidates,
        } => {
            if !lock(&inner.pending)
                .get(&pair)
                .is_some_and(|p| p.profile.id() == attempt)
            {
                return Err(error("stale AWG answer"));
            }
            let pending = lock(&inner.pending)
                .remove(&pair)
                .ok_or_else(|| error("AWG attempt cancelled"))?;
            let local_port = pending
                .socket
                .local_addr()
                .map_err(|_| error("AWG socket address unavailable"))?
                .port();
            let tunn = Tunn::new(
                pending.key,
                PublicKey::from(key),
                Some(pending.profile.psk),
                Some(1),
                rand::random(),
                None,
            );

            let link = session::start(
                pair.0,
                pair.1,
                pending.socket,
                tunn,
                pending.profile,
                candidates,
                inner.stopped.subscribe(),
            );
            if !lock(&inner.allowed).contains(&pair) {
                link.close();
                return Err(error("AWG membership ended"));
            }
            lock(&inner.links).insert(pair, link.clone());
            lock(&inner.port_by_pair).insert(pair, local_port);
            publish_when_up(Arc::downgrade(inner), pair, link, Some(pending.reply));
        }
    }
    Ok(())
}
fn publish_when_up(
    inner: Weak<Inner>,
    pair: Pair,
    link: Arc<PairLink>,
    reply: Option<oneshot::Sender<Result<SharedLink, TransportError>>>,
) {
    tokio::spawn(async move {
        let mut reply = reply;
        let result = tokio::time::timeout(Duration::from_secs(14), async {
            loop {
                if link.is_closed() || reply.as_ref().is_some_and(oneshot::Sender::is_closed) {
                    return Err(error("AWG pair closed during handshake"));
                }
                if link.has_authenticated_path() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            link.close();
            if let Some(reply) = reply.take() {
                let _ = reply.send(Err(error("AWG authenticated data path timed out")));
            }
            return;
        }
        let Some(inner) = inner.upgrade() else {
            link.close();
            return;
        };
        if !lock(&inner.allowed).contains(&pair) {
            link.close();
            return;
        }
        if link.is_closed()
            || !lock(&inner.links)
                .get(&pair)
                .is_some_and(|current| current.attempt == link.attempt)
        {
            link.close();
            return;
        }
        let shared: SharedLink = link.clone();
        if let Some(reply) = reply {
            if reply.send(Ok(shared)).is_err() {
                link.close();
            }
        } else if inner
            .inbound
            .try_send(InboundLink {
                network: pair.0,
                peer: pair.1,
                protocol: AWG_PROTOCOL.into(),
                link: shared,
            })
            .is_err()
        {
            link.close();
        }
    });
}
impl Drop for AwgTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[tokio::test]
    async fn concurrent_admission_is_bounded_across_networks_and_retirement_releases_slots() {
        let identity = tsunagi::identity::DeviceIdentity::generate();
        let transport = AwgTransport::new(identity.endpoint_id(), Ipv4Addr::LOCALHOST);
        let peer = tsunagi::identity::DeviceIdentity::generate().endpoint_id();
        std::thread::scope(|scope| {
            for thread in 0..8u8 {
                let transport = &transport;
                scope.spawn(move || {
                    for item in 0..32u8 {
                        let mut id = [0; 32];
                        id[0] = thread;
                        id[1] = item;
                        transport.allow_peer(NetworkId::from_bytes(id), peer);
                    }
                });
            }
        });
        assert_eq!(lock(&transport.inner.allowed).len(), 128);
        let network = lock(&transport.inner.allowed).iter().next().unwrap().0;
        transport.stop_network(network);
        let new = NetworkId::from_bytes([255; 32]);
        transport.allow_peer(new, peer);
        assert!(lock(&transport.inner.allowed).contains(&(new, peer)));
        assert_eq!(lock(&transport.inner.allowed).len(), 128);
        transport.shutdown();
        assert!(lock(&transport.inner.allowed).is_empty());
    }
    #[tokio::test]
    async fn private_negotiation_bounds_roles_and_membership_before_starting_engines() {
        let mut ids = [
            tsunagi::identity::DeviceIdentity::generate().endpoint_id(),
            tsunagi::identity::DeviceIdentity::generate().endpoint_id(),
        ];
        ids.sort_by_key(|id| *id.as_bytes());
        let peer = ids[0];
        let local = ids[1];
        let network = NetworkId::from_bytes([7; 32]);
        let transport = AwgTransport::new(local, Ipv4Addr::LOCALHOST);
        let offer = |version, key, addresses| Negotiation::Offer {
            version,
            profile: PairProfile::generate(),
            key,
            addresses,
        };
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 12345));
        let encode = |message: &Negotiation| postcard::to_stdvec(message).unwrap();
        let valid = encode(&offer(AWG_WIRE_VERSION, [1; 32], vec![address]));
        assert!(
            transport
                .on_control(network, peer, AWG_PROTOCOL, &valid)
                .is_err()
        );
        transport.allow_peer(network, peer);
        assert!(
            transport
                .on_control(network, peer, "wrong-protocol", &valid)
                .is_err()
        );
        assert!(
            transport
                .on_control(network, peer, AWG_PROTOCOL, &[0; 4097])
                .is_err()
        );
        for bytes in [
            encode(&offer(99, [1; 32], vec![address])),
            encode(&offer(AWG_WIRE_VERSION, [0; 32], vec![address])),
            encode(&offer(AWG_WIRE_VERSION, [1; 32], vec![])),
            encode(&offer(AWG_WIRE_VERSION, [1; 32], vec![address; 33])),
        ] {
            assert!(
                transport
                    .on_control(network, peer, AWG_PROTOCOL, &bytes)
                    .is_err()
            );
        }
        for len in 0..valid.len() {
            assert!(
                transport
                    .on_control(network, peer, AWG_PROTOCOL, &valid[..len])
                    .is_err()
            );
        }
        let wrong_role = AwgTransport::new(peer, Ipv4Addr::LOCALHOST);
        wrong_role.allow_peer(network, local);
        assert!(
            wrong_role
                .on_control(network, local, AWG_PROTOCOL, &valid)
                .is_err()
        );
        transport.forget_peer(network, peer);
        assert!(
            transport
                .on_control(network, peer, AWG_PROTOCOL, &valid)
                .is_err()
        );
        assert!(transport.overview(network).is_empty());
        transport.shutdown();
        wrong_role.shutdown();
    }
}
