//! The agent managing its own overlay interface.
//!
//! Everything here is real except the host: real agents, real control plane,
//! real iroh links, the real plugin lifecycle and the real reconciliation
//! rules. The host itself is a [`MockHost`], so what the agent would have
//! done to a machine's interfaces is asserted instead of done — which is how
//! this runs with no privileges and without touching the machine it is on.
//!
//! What the real provisioner adds on top of this is the netlink calls, and
//! only those.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use common::{config_with, network, wait_until};
use tempfile::TempDir;
use tsunagi::dataplane::IpPlugin;
use tsunagi::dataplane::wireguard::{
    Cidr, InterfaceState, LinkKind, ManagedTunFactory, MockHost, MockProvisioner, WireguardConfig,
    WireguardPlugin,
};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::NetworkId;
use tsunagi::state::DEFAULT_IPV4_RANGE;
use tsunagi::{Agent, NetworkStatus};

/// An agent whose overlay interface is applied to a pretend host.
struct HostedAgent {
    _dir: TempDir,
    agent: Agent,
    _plugin: Arc<WireguardPlugin>,
    host: MockHost,
}

impl HostedAgent {
    async fn spawn(discovery: &SharedMemoryDiscovery, tag: &str, host: MockHost) -> Self {
        let dir = TempDir::new().unwrap();
        let provisioner = Arc::new(MockProvisioner::new(host.clone()));
        let factory = Arc::new(ManagedTunFactory::new(provisioner));
        let config = WireguardConfig::new(dir.path().join("wireguard"))
            .with_reconcile(Duration::from_millis(20), Duration::from_millis(100));
        let plugin = WireguardPlugin::open(config).await.unwrap();
        let agent = Agent::spawn(
            config_with(dir.path(), discovery)
                .with_overlay_ipv4_range(Some(DEFAULT_IPV4_RANGE))
                .with_interface(factory, tag, 1280)
                .with_plugin(plugin.clone() as Arc<dyn IpPlugin>),
        )
        .await
        .unwrap();
        Self {
            _dir: dir,
            agent,
            _plugin: plugin,
            host,
        }
    }

    /// The interface name the plugin settled on for a network.
    /// The one interface this agent owns. Not per network.
    async fn interface(&self, _network: NetworkId) -> String {
        wait_until("the agent named its interface", || async {
            self.agent
                .overlay()
                .map(|overlay| overlay.interface)
                .filter(|name| !name.is_empty())
        })
        .await
    }

    /// Waits until the pretend host shows an interface in the given state.
    async fn wait_for_host<T>(
        &self,
        what: &str,
        name: &str,
        probe: impl Fn(Option<InterfaceState>) -> Option<T>,
    ) -> T {
        wait_until(what, || async { probe(self.host.get(name)) }).await
    }
}

fn v4(state: &InterfaceState) -> Vec<Ipv4Addr> {
    state
        .addresses
        .iter()
        .filter_map(|cidr| match cidr.addr {
            IpAddr::V4(addr) => Some(addr),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// Whether the overlay address has been put on the interface yet.
///
/// It is allocated and signed at the system level, so it arrives on a later
/// reconciliation than the interface itself rather than with it.
fn addressed(state: &InterfaceState) -> bool {
    !state.addresses.is_empty()
}

#[tokio::test]
async fn an_agent_creates_and_configures_its_own_overlay_interface() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("provision-create");
    let agent = HostedAgent::spawn(&discovery, "tsunp", MockHost::new()).await;

    let network_id = agent.agent.join_network(&name, &secret).await.unwrap();
    let interface = agent.interface(network_id).await;

    let state = agent
        .wait_for_host("the interface to be created", &interface, |state| state)
        .await;

    assert_eq!(state.kind, LinkKind::Tun);
    assert!(state.up, "the agent brought the link up itself");
    assert_eq!(state.mtu, 1280);

    let addresses = agent
        .wait_for_host("the allocated IPv4 address", &interface, |state| {
            state.map(|state| v4(&state)).filter(|v4| !v4.is_empty())
        })
        .await;
    assert_eq!(addresses.len(), 1);
    assert!(
        DEFAULT_IPV4_RANGE.contains(addresses[0]),
        "{:?} is outside {DEFAULT_IPV4_RANGE}",
        addresses[0]
    );

    agent.agent.shutdown().await;
}

#[tokio::test]
async fn an_interface_left_by_a_crashed_run_is_replaced_rather_than_tripped_over() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("provision-crash");

    // Work out the name this agent will use, then seed the host with what a
    // run that died would have left there: the interface, still carrying an
    // address from an allocation that no longer applies, with nothing holding
    // it open.
    let probe = HostedAgent::spawn(&discovery, "tsunc", MockHost::new()).await;
    let network_id = probe.agent.join_network(&name, &secret).await.unwrap();
    let interface = probe.interface(network_id).await;
    probe.agent.shutdown().await;

    let host = MockHost::new();
    let stale = Cidr::new(IpAddr::V4(Ipv4Addr::new(10, 13, 37, 178)), 24).unwrap();
    host.insert_stale_tun(&interface, vec![stale]);

    let agent = HostedAgent::spawn(&discovery, "tsunc", host).await;
    let network_id = agent.agent.join_network(&name, &secret).await.unwrap();
    assert_eq!(agent.interface(network_id).await, interface);

    // Waited on directly rather than on "it has some address": the address
    // this agent was allocated arrives a reconciliation after the interface
    // does, and in between the leftover is still the only one there.
    let state = agent
        .wait_for_host("the stale address to be replaced", &interface, |state| {
            state.filter(|state| {
                state.attached && addressed(state) && !state.addresses.contains(&stale)
            })
        })
        .await;
    assert!(
        !state.addresses.contains(&stale),
        "the stale address is gone: {:?}",
        state.addresses
    );

    agent.agent.shutdown().await;
}

#[tokio::test]
async fn an_interface_belonging_to_something_else_is_left_alone() {
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("provision-foreign");

    let probe = HostedAgent::spawn(&discovery, "tsunf", MockHost::new()).await;
    let network_id = probe.agent.join_network(&name, &secret).await.unwrap();
    let interface = probe.interface(network_id).await;
    probe.agent.shutdown().await;

    // Somebody else's bridge happens to hold the name.
    let host = MockHost::new();
    let theirs = InterfaceState {
        kind: LinkKind::Foreign("bridge".into()),
        attached: true,
        up: true,
        mtu: 1500,
        addresses: vec![Cidr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 9, 1)), 24).unwrap()],
    };
    host.insert(&interface, theirs.clone());

    let agent = HostedAgent::spawn(&discovery, "tsunf", host).await;
    agent.agent.join_network(&name, &secret).await.unwrap();

    // Give the plugin several reconciliation rounds to do the wrong thing.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        agent.host.get(&interface),
        Some(theirs),
        "the foreign interface must be untouched"
    );

    // The control plane is unaffected by the data plane refusing.
    assert!(matches!(
        agent.agent.network_status(network_id).await,
        Ok(NetworkStatus { .. })
    ));

    agent.agent.shutdown().await;
}

#[tokio::test]
async fn leaving_a_network_takes_its_address_off_the_interface_but_not_the_interface() {
    // The interface belongs to the agent, so it outlives any one network:
    // another may still be using it. What a network takes with it is its own
    // address.
    let discovery = SharedMemoryDiscovery::new();
    let (name, secret) = network("provision-cleanup");
    let agent = HostedAgent::spawn(&discovery, "tsunx", MockHost::new()).await;

    let network_id = agent.agent.join_network(&name, &secret).await.unwrap();
    let interface = agent.interface(network_id).await;
    agent
        .wait_for_host("the address to be assigned", &interface, |state| {
            state.filter(addressed)
        })
        .await;

    agent.agent.deactivate_network(network_id).await.unwrap();

    let state = agent
        .wait_for_host("the address to be withdrawn", &interface, |state| {
            state.filter(|state| !addressed(state))
        })
        .await;
    assert_eq!(state.kind, LinkKind::Tun, "the interface is still there");

    // And it goes when the agent does.
    agent.agent.shutdown().await;
    assert!(
        agent.host.names().is_empty(),
        "nothing is left behind: {:?}",
        agent.host.names()
    );
}
