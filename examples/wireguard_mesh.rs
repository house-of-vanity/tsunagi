//! Two agents forming a WireGuard overlay, printed step by step.
//!
//! ```text
//! cargo run --example wireguard_mesh
//! ```
//!
//! By default it uses the in-memory backend, so it needs no privileges and
//! changes nothing on the host: it shows the configuration each agent *would*
//! apply. Pass `--real` to drive the actual `wg` and `ip` tools instead, which
//! needs Linux and `CAP_NET_ADMIN`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tsunagi::config::{AgentConfig, StoragePaths, TransportPolicy};
use tsunagi::dataplane::IpPlugin;
use tsunagi::dataplane::wireguard::{
    AdvertisePolicy, PortPolicy, RecordingBackend, WireguardBackend, WireguardConfig,
    WireguardPlugin,
};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkName, NetworkSecret};
use tsunagi::{Agent, NetworkId, Result};

struct Node {
    agent: Agent,
    plugin: Arc<WireguardPlugin>,
    backend: Option<RecordingBackend>,
}

async fn start(
    root: &std::path::Path,
    discovery: &SharedMemoryDiscovery,
    prefix: &str,
    advertise: IpAddr,
    real: bool,
) -> Result<Node> {
    let recording = (!real).then(RecordingBackend::new);
    let backend: Arc<dyn WireguardBackend> = match &recording {
        Some(backend) => Arc::new(backend.clone()),
        None => Arc::new(
            tsunagi::dataplane::wireguard::WgToolBackend::new()
                .map_err(|err| tsunagi::Error::Discovery(err.to_string()))?,
        ),
    };

    let wireguard = WireguardConfig::new(root.join("wireguard"))
        .with_interface_prefix(prefix)
        .with_advertise(AdvertisePolicy::Explicit(vec![advertise]))
        .with_ports(PortPolicy::Fixed(if real { 51820 } else { 51821 }));
    let plugin = WireguardPlugin::open(wireguard, backend)
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
        backend: recording,
    })
}

fn report(label: &str, node: &Node, network: NetworkId) {
    let Some(view) = node.plugin.overview(network) else {
        println!("{label}: the plugin has not prepared this network yet");
        return;
    };
    println!("\n{label}");
    println!("  interface      {}", view.interface);
    println!("  public key     {}", view.public_key);
    println!(
        "  overlay        {} in {}",
        view.overlay_address, view.overlay_prefix
    );
    println!("  listening on   :{}", view.listen_port);
    println!("  advertising    {:?}", view.advertised);
    for peer in &view.peers {
        println!(
            "  peer {} -> {} via {:?}",
            peer.public_key.fmt_short(),
            peer.overlay_address,
            peer.endpoint
        );
    }
    if let Some(backend) = &node.backend
        && let Some(state) = backend.state(&view.interface)
    {
        println!("  applied        {} peer(s)", state.peers.len());
        for peer in &state.peers {
            println!(
                "    AllowedIPs for {} = {:?}",
                peer.public_key.fmt_short(),
                peer.allowed_ips
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let real = std::env::args().any(|arg| arg == "--real");
    if real {
        println!("driving the real wg/ip tools; this needs Linux and CAP_NET_ADMIN\n");
    } else {
        println!("using the in-memory backend; nothing on this host is changed\n");
    }

    let root = match tempfile::TempDir::new() {
        Ok(root) => root,
        Err(err) => {
            eprintln!("cannot create a temporary directory: {err}");
            return Ok(());
        }
    };
    let discovery = SharedMemoryDiscovery::new();

    let alice = start(
        &root.path().join("alice"),
        &discovery,
        "wga",
        "10.88.0.1".parse().unwrap_or(IpAddr::from([10, 88, 0, 1])),
        real,
    )
    .await?;
    let bob = start(
        &root.path().join("bob"),
        &discovery,
        "wgb",
        "10.88.0.2".parse().unwrap_or(IpAddr::from([10, 88, 0, 2])),
        real,
    )
    .await?;

    let name = NetworkName::new("wireguard-demo")?;
    let secret = NetworkSecret::generate();
    println!(
        "network secret (keep it safe): {}",
        secret.encode().as_str()
    );

    let network = alice.agent.join_network(&name, &secret).await?;
    bob.agent.join_network(&name, &secret).await?;
    println!("network id: {network}");

    // Wait until both sides configured one peer, under a bounded deadline.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let ready = [&alice, &bob].iter().all(|node| {
            let Some(view) = node.plugin.overview(network) else {
                return false;
            };
            if view.peers.len() != 1 {
                return false;
            }
            // With the in-memory backend we can also wait for the
            // configuration to actually be applied.
            match &node.backend {
                Some(backend) => backend
                    .state(&view.interface)
                    .map(|state| state.peers.len() == 1)
                    .unwrap_or(false),
                None => true,
            }
        });
        if ready {
            break;
        }
        if std::time::Instant::now() > deadline {
            println!("\nthe overlay did not converge in time");
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    report("alice", &alice, network);
    report("bob", &bob, network);

    println!("\nshutting down; the plugin removes what it created");
    alice.agent.shutdown().await;
    bob.agent.shutdown().await;
    Ok(())
}
