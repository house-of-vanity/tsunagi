//! The one interface an agent owns, and the loop that moves packets across it.
//!
//! Outbound, a packet read from the interface is looked up in the
//! [`RoutingTable`] and handed to whatever can carry it to that peer.
//! Inbound, a packet a protocol has decrypted is checked against the same
//! table and written to the interface.
//!
//! Neither direction knows which protocol is involved, and that is the
//! point: the interface, the addresses on it and the decision of whose
//! packet this is all belong here, so several protocols can be carrying
//! traffic at once without any of them owning the thing they are carrying it
//! for.
//!
//! # What is counted rather than hidden
//!
//! A packet with nowhere to go, a packet from a peer that does not hold its
//! source address, a multicast packet the operating system emitted anyway:
//! each is dropped and counted, with a sample kept for the first kind,
//! because "the overlay is quiet" and "the overlay is dropping everything"
//! look identical without them.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use iroh::EndpointId;
use tokio::task::JoinHandle;

use crate::identity::NetworkId;

use super::packet::IpHeader;
use super::router::{Route, RoutingTable};
use super::tun::{TunDevice, TunFactory, TunRequest};
use super::{Cidr, OverlayError};

/// Carries one packet to a peer, by whatever protocol currently can.
///
/// Implemented by the layer that knows which protocols are live for which
/// peers. The interface does not: it asks for a packet to reach a peer and
/// is told whether that was possible.
pub trait PacketCarrier: Send + Sync + 'static {
    /// Carries a packet, answering `false` if nothing can right now.
    fn carry(&self, route: Route, packet: Bytes) -> bool;
}

/// Why a decrypted packet was not written to the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// It was not a packet this agent could read.
    Malformed,
    /// The overlay is IPv4; anything else has no owner here.
    WrongFamily,
    /// The sending peer does not hold the source address it used.
    WrongSource,
    /// Broadcast disabled, outside this domain, or malformed/non-UDP.
    BroadcastDenied,
    /// The packet terminates outside this host's network address/domain.
    WrongDestination,
}

/// Counters for one interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    /// Packets handed to a protocol.
    pub sent: u64,
    /// Broadcast copies handed to recipient tunnels.
    pub broadcast_sent: u64,
    /// Broadcast packets admitted to this host.
    pub broadcast_received: u64,
    /// Broadcasts refused by domain policy or packet validation.
    pub broadcast_dropped: u64,
    /// Packets written to the operating system.
    pub received: u64,
    /// Packets for an address nobody in any network holds.
    pub unroutable: u64,
    /// One such destination, so the number can be acted on.
    pub unroutable_sample: Option<IpAddr>,
    /// Packets nothing could carry, though their destination was known.
    pub undeliverable: u64,
    /// Unsupported multicast or unspecified-destination packets.
    pub multicast: u64,
    /// Packets from a peer that does not hold the source address used.
    pub wrong_source: u64,
    /// Decrypted packets addressed outside the receiving network's local host.
    pub wrong_destination: u64,
    /// Packets that could not be read at all.
    pub malformed: u64,
}

#[derive(Debug, Default)]
struct Tally {
    sent: AtomicU64,
    broadcast_sent: AtomicU64,
    broadcast_received: AtomicU64,
    broadcast_dropped: AtomicU64,
    received: AtomicU64,
    unroutable: AtomicU64,
    undeliverable: AtomicU64,
    multicast: AtomicU64,
    wrong_source: AtomicU64,
    wrong_destination: AtomicU64,
    malformed: AtomicU64,
    sample: std::sync::Mutex<Option<IpAddr>>,
}

impl Tally {
    fn snapshot(&self) -> Counters {
        Counters {
            sent: self.sent.load(Ordering::Relaxed),
            broadcast_sent: self.broadcast_sent.load(Ordering::Relaxed),
            broadcast_received: self.broadcast_received.load(Ordering::Relaxed),
            broadcast_dropped: self.broadcast_dropped.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
            unroutable: self.unroutable.load(Ordering::Relaxed),
            unroutable_sample: match self.sample.lock() {
                Ok(guard) => *guard,
                Err(poisoned) => *poisoned.into_inner(),
            },
            undeliverable: self.undeliverable.load(Ordering::Relaxed),
            multicast: self.multicast.load(Ordering::Relaxed),
            wrong_source: self.wrong_source.load(Ordering::Relaxed),
            wrong_destination: self.wrong_destination.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
        }
    }

    fn note_unroutable(&self, destination: IpAddr) {
        self.unroutable.fetch_add(1, Ordering::Relaxed);
        // The first one is kept. A later sample would keep overwriting the
        // one a reader is looking at.
        let mut guard = match self.sample.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.is_none() {
            *guard = Some(destination);
        }
    }
}

/// The overlay interface.
#[derive(Debug)]
pub struct Interface {
    device: Arc<dyn TunDevice>,
    factory: Arc<dyn TunFactory>,
    name: String,
    mtu: u32,
    routes: Arc<RoutingTable>,
    tally: Arc<Tally>,
    /// What was last applied to the host, so an unchanged table is not
    /// re-applied on every pass.
    applied: std::sync::Mutex<Vec<Cidr>>,
    task: std::sync::Mutex<Option<JoinHandle<()>>>,
    sync_lock: Arc<tokio::sync::Mutex<()>>,
}

impl Interface {
    /// Creates the interface and starts moving packets.
    pub async fn start(
        factory: Arc<dyn TunFactory>,
        name: impl Into<String>,
        mtu: u32,
        routes: Arc<RoutingTable>,
        carrier: Arc<dyn PacketCarrier>,
    ) -> Result<Self, OverlayError> {
        let name = name.into();
        let device = factory.create(TunRequest::bare(name.clone(), mtu)).await?;
        let tally = Arc::new(Tally::default());

        let task = {
            let device = Arc::clone(&device);
            let routes = Arc::clone(&routes);
            let tally = Arc::clone(&tally);
            tokio::spawn(async move {
                while let Some(packet) = device.recv().await {
                    let Some(header) = IpHeader::parse(&packet) else {
                        tally.malformed.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let destination = header.destination();
                    if let (IpAddr::V4(source), IpAddr::V4(destination)) =
                        (header.source(), destination)
                        && routes.is_broadcast(destination)
                    {
                        let recipients = super::broadcast::valid_udp(&packet)
                            .then(|| routes.broadcast_recipients(source, destination))
                            .flatten();
                        if let Some(recipients) = recipients {
                            for &route in recipients.iter() {
                                if carrier.carry(route, packet.clone()) {
                                    tally.sent.fetch_add(1, Ordering::Relaxed);
                                    tally.broadcast_sent.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    tally.undeliverable.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        } else {
                            tally.broadcast_dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    }
                    if is_multicast_or_broadcast(destination) {
                        // The operating system emits these on any interface.
                        // The overlay is a set of point-to-point tunnels and
                        // has nowhere to put them; expected, not a fault.
                        tally.multicast.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let Some(route) = routes.route_v4(destination) else {
                        tally.note_unroutable(destination);
                        continue;
                    };
                    if carrier.carry(route, packet) {
                        tally.sent.fetch_add(1, Ordering::Relaxed);
                    } else {
                        tally.undeliverable.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        };

        Ok(Self {
            device,
            factory,
            name,
            mtu,
            routes,
            tally,
            applied: std::sync::Mutex::new(Vec::new()),
            task: std::sync::Mutex::new(Some(task)),
            sync_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Brings the addresses on the host in line with the routing table.
    ///
    /// Called whenever a network agrees a different address for this agent.
    /// The interface is never recreated for it: that would drop every tunnel
    /// riding on it for the sake of one address.
    pub async fn sync_addresses(&self) -> Result<(), OverlayError> {
        let _guard = self.sync_lock.lock().await;
        let wanted = self.wanted_addresses();
        {
            let applied = match self.applied.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            };
            if applied == wanted {
                return Ok(());
            }
        }

        // Every address this agent holds, in every network it is in. The
        // plan is exhaustive by contract, so this is also what takes an
        // address off the interface when a network is left or stopped.
        let request = TunRequest {
            name: self.name.clone(),
            addresses: wanted.clone(),
            mtu: self.mtu,
        };
        self.factory.reconfigure(request).await?;
        match self.applied.lock() {
            Ok(mut guard) => *guard = wanted,
            Err(poisoned) => *poisoned.into_inner() = wanted,
        }
        Ok(())
    }

    /// The interface name the operating system gave.
    pub fn name(&self) -> &str {
        self.device.name()
    }

    /// The interface MTU.
    pub fn mtu(&self) -> u32 {
        self.device.mtu()
    }

    /// Whether this interface exists on the host.
    ///
    /// `false` with an in-memory device, where tunnels run and packets move
    /// but the operating system knows nothing about any of it. Anything that
    /// would configure the host — a route, a resolver setting, a complaint
    /// that an address is missing from a link — has to ask first.
    pub fn on_host(&self) -> bool {
        self.factory.on_host()
    }

    /// Removes the interface from the host.
    pub async fn remove(&self) {
        // The packet loop holds the device open, and it ends only when the
        // device reports end of stream — which a real interface never does
        // while it exists. Stop it directly before destroying the interface.
        let task = match self.task.lock() {
            Ok(mut guard) => guard.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        self.factory.destroy(self.device.name()).await;
    }

    /// The counters as they stand.
    pub fn counters(&self) -> Counters {
        self.tally.snapshot()
    }

    /// Writes a packet a protocol decrypted to the operating system.
    ///
    /// The source is checked against what the network agreed that peer
    /// holds. A protocol proved *who* sent the packet; only this level knows
    /// what that member is entitled to say.
    pub async fn deliver(
        &self,
        network: NetworkId,
        peer: EndpointId,
        packet: Bytes,
    ) -> Result<(), Rejected> {
        let Some(header) = IpHeader::parse(&packet) else {
            self.tally.malformed.fetch_add(1, Ordering::Relaxed);
            return Err(Rejected::Malformed);
        };
        let IpAddr::V4(source) = header.source() else {
            self.tally.wrong_source.fetch_add(1, Ordering::Relaxed);
            return Err(Rejected::WrongFamily);
        };
        if !self.routes.may_send_from(network, peer, source) {
            self.tally.wrong_source.fetch_add(1, Ordering::Relaxed);
            return Err(Rejected::WrongSource);
        }
        let broadcast = match header.destination() {
            IpAddr::V4(destination) if self.routes.is_broadcast(destination) => {
                if !super::broadcast::valid_udp(&packet)
                    || !self.routes.accepts_broadcast(network, peer, destination)
                {
                    self.tally.broadcast_dropped.fetch_add(1, Ordering::Relaxed);
                    return Err(Rejected::BroadcastDenied);
                }
                true
            }
            IpAddr::V4(destination) if self.routes.is_local_destination(network, destination) => {
                false
            }
            _ => {
                self.tally.wrong_destination.fetch_add(1, Ordering::Relaxed);
                return Err(Rejected::WrongDestination);
            }
        };
        // Remote broadcasts terminate here. Only local TUN ingress can fan out.
        if self.device.send(packet).await.is_ok() {
            if broadcast {
                self.tally
                    .broadcast_received
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.tally.received.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// The addresses the interface should be carrying, from the table.
    pub fn wanted_addresses(&self) -> Vec<Cidr> {
        self.routes
            .local_addresses()
            .into_iter()
            .filter_map(|(address, prefix_len)| Cidr::new(address.into(), prefix_len).ok())
            .collect()
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.task.lock()
            && let Some(task) = guard.take()
        {
            task.abort();
        }
    }
}

impl RoutingTable {
    /// The route for a destination, when it is one the overlay carries.
    fn route_v4(&self, destination: IpAddr) -> Option<Route> {
        match destination {
            IpAddr::V4(address) => self.route(address),
            // The overlay is IPv4. An IPv6 packet has no owner here, and
            // counting it as unroutable is the truth rather than a fault.
            IpAddr::V6(_) => None,
        }
    }
}

/// Whether an address is one the overlay has nowhere to send.
fn is_multicast_or_broadcast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_multicast() || address.is_broadcast() || address == Ipv4Addr::UNSPECIFIED
        }
        IpAddr::V6(address) => address.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[tokio::test]
    async fn an_in_memory_interface_says_it_is_not_on_the_host() {
        // Everything that would configure the operating system for this
        // interface asks first, and the answer here is no: the name is real
        // to the agent and to nothing else. A real `tsun0` belonging to
        // another agent looks identical from here, so acting on the name
        // alone would configure that one.
        let interface = Interface::start(
            Arc::new(crate::overlay::MemoryTunFactory::new()),
            "tsun0",
            1280,
            Arc::new(RoutingTable::new()),
            Arc::new(Recorder::default()),
        )
        .await
        .unwrap();

        assert_eq!(interface.name(), "tsun0");
        assert!(!interface.on_host());
        interface.remove().await;
    }
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};
    use crate::overlay::router::NetworkRoutes;
    use crate::overlay::tun::{MemoryTun, MemoryTunFactory};

    fn network(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes(vec![7u8; 32]).unwrap(),
        )
        .network_id()
    }

    fn peer(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn addr(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 13, 37, last)
    }

    fn ipv4(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Bytes {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        let total = (20 + payload.len()) as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet.extend_from_slice(payload);
        Bytes::from(packet)
    }

    #[tokio::test]
    async fn broadcast_ingress_is_validated_and_remote_delivery_never_refloods() {
        use super::super::broadcast::BroadcastPolicy;
        use std::collections::HashSet;
        let (interface, device, routes, carrier, id) = interface(false).await;
        let enabled = BroadcastPolicy {
            enabled: true,
            peers: HashSet::from([peer(2)]),
        };
        routes.set_broadcast(id, enabled.clone());
        let packet = ipv4(addr(2), Ipv4Addr::BROADCAST, &[0, 1, 0, 2, 0, 8, 0, 0]);
        interface
            .deliver(id, peer(2), packet.clone())
            .await
            .unwrap();
        assert_eq!(device.pop_to_os().await.unwrap(), packet);
        assert!(
            carrier.carried().is_empty(),
            "remote ingress never originates a fanout"
        );
        assert_eq!(
            interface.deliver(id, peer(3), packet.clone()).await,
            Err(Rejected::WrongSource)
        );
        assert_eq!(
            interface
                .deliver(id, peer(2), ipv4(addr(2), Ipv4Addr::BROADCAST, b"bad"))
                .await,
            Err(Rejected::BroadcastDenied)
        );
        routes.set_broadcast(
            id,
            BroadcastPolicy {
                enabled: false,
                ..enabled
            },
        );
        assert_eq!(
            interface.deliver(id, peer(2), packet).await,
            Err(Rejected::BroadcastDenied)
        );
        // An authenticated sender cannot use TUN as a gateway to a physical LAN.
        assert_eq!(
            interface
                .deliver(
                    id,
                    peer(2),
                    ipv4(
                        addr(2),
                        "192.168.1.255".parse().unwrap(),
                        &[0, 1, 0, 2, 0, 8, 0, 0]
                    )
                )
                .await,
            Err(Rejected::WrongDestination)
        );
        device.push_from_os(ipv4(
            addr(1),
            Ipv4Addr::BROADCAST,
            &[0, 1, 0, 2, 0, 8, 0, 0],
        ));
        wait_for(&interface, |c| c.broadcast_dropped.saturating_sub(2)).await;
        assert!(carrier.carried().is_empty());
        assert_eq!(interface.counters().received, 1);
        interface.remove().await;
    }

    /// Records what it was asked to carry, and can refuse.
    #[derive(Debug, Default)]
    struct Recorder {
        carried: std::sync::Mutex<Vec<(Route, Bytes)>>,
        refuse: bool,
    }

    impl PacketCarrier for Recorder {
        fn carry(&self, route: Route, packet: Bytes) -> bool {
            if self.refuse {
                return false;
            }
            match self.carried.lock() {
                Ok(mut guard) => guard.push((route, packet)),
                Err(poisoned) => poisoned.into_inner().push((route, packet)),
            }
            true
        }
    }

    impl Recorder {
        fn carried(&self) -> Vec<(Route, Bytes)> {
            match self.carried.lock() {
                Ok(guard) => guard.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }
    }

    async fn interface(
        refuse: bool,
    ) -> (
        Interface,
        Arc<MemoryTun>,
        Arc<RoutingTable>,
        Arc<Recorder>,
        NetworkId,
    ) {
        let id = network("interface");
        let routes = Arc::new(RoutingTable::new());
        routes
            .set_network(
                id,
                NetworkRoutes {
                    broadcast: Default::default(),
                    range: Some("10.13.37.0/24".parse().unwrap()),
                    local: Some(addr(1)),
                    peers: vec![(addr(2), peer(2)), (addr(3), peer(3))],
                },
            )
            .unwrap();
        let carrier = Arc::new(Recorder {
            carried: std::sync::Mutex::new(Vec::new()),
            refuse,
        });
        let factory = Arc::new(MemoryTunFactory::new());
        let interface = Interface::start(
            Arc::clone(&factory) as Arc<dyn TunFactory>,
            "tsuntest",
            1280,
            Arc::clone(&routes),
            Arc::clone(&carrier) as Arc<dyn PacketCarrier>,
        )
        .await
        .unwrap();
        // The factory keeps what it made, which is how a test reaches the
        // device the interface is using without exposing it.
        let device = factory.device("tsuntest").expect("the device was created");
        (interface, device, routes, carrier, id)
    }

    /// Waits for a counter to move, so the interface's own task has run.
    async fn wait_for(interface: &Interface, pick: impl Fn(&Counters) -> u64) {
        for _ in 0..400 {
            if pick(&interface.counters()) > 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("the counter never moved: {:?}", interface.counters());
    }

    #[tokio::test]
    async fn a_packet_leaving_the_interface_goes_to_the_peer_that_owns_it() {
        let (interface, device, _routes, carrier, id) = interface(false).await;
        device.push_from_os(ipv4(addr(1), addr(2), b"hello"));

        wait_for(&interface, |counters| counters.sent).await;
        let carried = carrier.carried();
        assert_eq!(carried.len(), 1);
        assert_eq!(carried[0].0.peer, peer(2));
        assert_eq!(carried[0].0.network, id);
        assert_eq!(&carried[0].1[20..], b"hello");
    }

    #[tokio::test]
    async fn a_packet_for_nobody_is_counted_with_a_sample_and_not_sent() {
        // Counted rather than dropped quietly: without the number and an
        // example of it, "the overlay is quiet" and "the overlay is dropping
        // everything" look the same.
        let (interface, device, _routes, carrier, _id) = interface(false).await;
        let nowhere = Ipv4Addr::new(10, 13, 37, 200);
        device.push_from_os(ipv4(addr(1), nowhere, b"lost"));

        wait_for(&interface, |counters| counters.unroutable).await;
        assert_eq!(
            interface.counters().unroutable_sample,
            Some(IpAddr::V4(nowhere))
        );
        assert!(carrier.carried().is_empty(), "nothing was flooded");
    }

    #[tokio::test]
    async fn multicast_is_expected_and_never_carried() {
        let (interface, device, _routes, carrier, _id) = interface(false).await;
        device.push_from_os(ipv4(addr(1), Ipv4Addr::new(224, 0, 0, 251), b"mdns"));

        wait_for(&interface, |counters| counters.multicast).await;
        assert_eq!(interface.counters().unroutable, 0, "not a routing failure");
        assert!(carrier.carried().is_empty());
    }

    #[tokio::test]
    async fn a_packet_nothing_can_carry_is_counted_separately() {
        // Distinct from unroutable: the destination is known, there is just
        // no live protocol for it. The two want different answers.
        let (interface, device, _routes, _carrier, _id) = interface(true).await;
        device.push_from_os(ipv4(addr(1), addr(2), b"no link"));

        wait_for(&interface, |counters| counters.undeliverable).await;
        let counters = interface.counters();
        assert_eq!(counters.sent, 0);
        assert_eq!(counters.unroutable, 0);
    }

    #[tokio::test]
    async fn a_decrypted_packet_from_its_owner_reaches_the_operating_system() {
        let (interface, device, _routes, _carrier, id) = interface(false).await;
        interface
            .deliver(id, peer(2), ipv4(addr(2), addr(1), b"inbound"))
            .await
            .unwrap();

        let written = tokio::time::timeout(std::time::Duration::from_secs(5), device.pop_to_os())
            .await
            .expect("the packet reaches the interface")
            .unwrap();
        assert_eq!(&written[20..], b"inbound");
        assert_eq!(interface.counters().received, 1);
    }

    #[tokio::test]
    async fn a_peer_cannot_send_from_an_address_it_does_not_hold() {
        let (interface, _device, _routes, _carrier, id) = interface(false).await;

        // Another member's address.
        assert_eq!(
            interface
                .deliver(id, peer(2), ipv4(addr(3), addr(1), b"spoofed"))
                .await,
            Err(Rejected::WrongSource)
        );
        // And this agent's own.
        assert_eq!(
            interface
                .deliver(id, peer(2), ipv4(addr(1), addr(1), b"spoofed"))
                .await,
            Err(Rejected::WrongSource)
        );
        assert_eq!(interface.counters().wrong_source, 2);
        assert_eq!(interface.counters().received, 0);
    }

    #[tokio::test]
    async fn an_unreadable_or_wrong_family_packet_is_refused_without_panicking() {
        let (interface, _device, _routes, _carrier, id) = interface(false).await;

        assert_eq!(
            interface.deliver(id, peer(2), Bytes::new()).await,
            Err(Rejected::Malformed)
        );
        assert_eq!(
            interface
                .deliver(id, peer(2), Bytes::from_static(&[0xff; 8]))
                .await,
            Err(Rejected::Malformed)
        );

        // An IPv6 packet: readable, but the overlay has no owner for it.
        let mut six = vec![0u8; 40];
        six[0] = 0x60;
        assert_eq!(
            interface.deliver(id, peer(2), Bytes::from(six)).await,
            Err(Rejected::WrongFamily)
        );
    }

    #[tokio::test]
    async fn the_wanted_addresses_follow_the_table() {
        let (interface, _device, routes, _carrier, id) = interface(false).await;
        assert_eq!(
            interface.wanted_addresses(),
            vec![Cidr::new(addr(1).into(), 24).unwrap()]
        );

        // The network agreed a different address for us.
        routes
            .set_network(
                id,
                NetworkRoutes {
                    broadcast: Default::default(),
                    range: Some("10.13.37.0/24".parse().unwrap()),
                    local: Some(addr(9)),
                    peers: vec![(addr(2), peer(2))],
                },
            )
            .unwrap();
        assert_eq!(
            interface.wanted_addresses(),
            vec![Cidr::new(addr(9).into(), 24).unwrap()]
        );
    }
}
