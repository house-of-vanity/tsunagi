//! Two agents forming a WireGuard overlay and exchanging a real IP packet.
//!
//! ```text
//! cargo run --example wireguard_mesh
//! ```
//!
//! It uses an in-memory packet interface, so it needs no privileges and
//! changes nothing on the host: the WireGuard handshake, the encryption and
//! the transport over iroh are all real, only the TUN device is simulated.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tsunagi::config::{AgentConfig, StoragePaths, TransportPolicy};
use tsunagi::dataplane::IpPlugin;
use tsunagi::dataplane::wireguard::{
    MemoryTun, MemoryTunFactory, WireguardConfig, WireguardPlugin,
};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkName, NetworkSecret};
use tsunagi::{Agent, NetworkId, Result};

struct Node {
    agent: Agent,
    plugin: Arc<WireguardPlugin>,
    tuns: MemoryTunFactory,
}

async fn start(
    root: &std::path::Path,
    discovery: &SharedMemoryDiscovery,
    prefix: &str,
) -> Result<Node> {
    let tuns = MemoryTunFactory::new();
    let plugin = WireguardPlugin::open(
        WireguardConfig::new(root.join("wireguard")).with_interface_prefix(prefix),
        Arc::new(tuns.clone()),
    )
    .await
    .map_err(|err| tsunagi::Error::Discovery(err.to_string()))?;

    let agent = Agent::spawn(
        AgentConfig::new(StoragePaths::under(root))
            .with_transport(TransportPolicy::LocalOnly)
            .with_loopback_bind()
            .with_discovery(Arc::new(discovery.clone()))
            .with_discovery_interval(Duration::from_millis(200))
            .with_plugin(plugin.clone() as Arc<dyn IpPlugin>),
    )
    .await?;

    Ok(Node {
        agent,
        plugin,
        tuns,
    })
}

fn report(label: &str, node: &Node, network: NetworkId) {
    let Some(view) = node.plugin.overview(network) else {
        println!("{label}: not prepared yet");
        return;
    };
    println!("\n{label}");
    println!("  interface   {} (mtu {})", view.interface, view.mtu);
    println!("  public key  {}", view.public_key);
    println!(
        "  overlay     {} in {}/{}",
        view.overlay_address, view.overlay_prefix, view.overlay_prefix_len
    );
    for peer in &view.peers {
        match &peer.tunnel {
            Some(tunnel) => println!(
                "  peer {} at {} — handshake {:?}, tx {} rx {}, path {}",
                peer.public_key.fmt_short(),
                peer.overlay_address,
                tunnel.health.since_handshake,
                tunnel.stats.tx_packets,
                tunnel.stats.rx_packets,
                tunnel.path
            ),
            None => println!(
                "  peer {} at {} — no data link yet",
                peer.public_key.fmt_short(),
                peer.overlay_address
            ),
        }
    }
}

fn ipv6_packet(source: Ipv6Addr, destination: Ipv6Addr, payload: &[u8]) -> Bytes {
    let mut packet = Vec::with_capacity(40 + payload.len());
    packet.push(6 << 4);
    packet.extend_from_slice(&[0, 0, 0]);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.push(59);
    packet.push(64);
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.octets());
    packet.extend_from_slice(payload);
    Bytes::from(packet)
}

fn overlay_of(node: &Node, network: NetworkId) -> Option<Ipv6Addr> {
    match node.plugin.overview(network)?.overlay_address {
        IpAddr::V6(addr) => Some(addr),
        IpAddr::V4(_) => None,
    }
}

fn tun_of(node: &Node, network: NetworkId) -> Option<Arc<MemoryTun>> {
    let view = node.plugin.overview(network)?;
    node.tuns.device(&view.interface)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    println!("in-memory packet interface: nothing on this host is changed\n");

    let root = match tempfile::TempDir::new() {
        Ok(root) => root,
        Err(err) => {
            eprintln!("cannot create a temporary directory: {err}");
            return Ok(());
        }
    };
    let discovery = SharedMemoryDiscovery::new();

    let alice = start(&root.path().join("alice"), &discovery, "wga").await?;
    let bob = start(&root.path().join("bob"), &discovery, "wgb").await?;

    let name = NetworkName::new("wireguard-demo")?;
    let secret = NetworkSecret::generate();
    println!(
        "network secret (keep it safe): {}",
        secret.encode().as_str()
    );

    let network = alice.agent.join_network(&name, &secret).await?;
    bob.agent.join_network(&name, &secret).await?;
    println!("network id: {network}");

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let ready = [&alice, &bob].iter().all(|node| {
            node.plugin
                .overview(network)
                .map(|view| view.established_peers() == 1)
                .unwrap_or(false)
        });
        if ready {
            break;
        }
        if Instant::now() > deadline {
            println!("\nthe overlay did not come up in time");
            report("alice", &alice, network);
            report("bob", &bob, network);
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // A real IP packet, encrypted by WireGuard and carried over iroh.
    if let (Some(from), Some(to), Some(tun_a), Some(tun_b)) = (
        overlay_of(&alice, network),
        overlay_of(&bob, network),
        tun_of(&alice, network),
        tun_of(&bob, network),
    ) {
        tun_a.push_from_os(ipv6_packet(from, to, b"hello over the overlay"));
        match tokio::time::timeout(Duration::from_secs(5), tun_b.pop_to_os()).await {
            Ok(Some(packet)) => println!(
                "\nbob received {} bytes from {}: {:?}",
                packet.len(),
                from,
                String::from_utf8_lossy(&packet[40..])
            ),
            _ => println!("\nthe packet did not arrive"),
        }
    }

    report("alice", &alice, network);
    report("bob", &bob, network);

    println!("\nshutting down; the plugin removes what it created");
    alice.agent.shutdown().await;
    bob.agent.shutdown().await;
    Ok(())
}
