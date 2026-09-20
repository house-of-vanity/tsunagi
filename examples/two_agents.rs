//! A tiny runnable demonstration of the library.
//!
//! Run it with:
//!
//! ```text
//! cargo run --example two_agents
//! ```
//!
//! It starts two agents in one process, on loopback only, joins them to the
//! same network space and exchanges one request/response. It is a demo, not a
//! substitute for the integration tests in `tests/`.

use std::sync::Arc;
use std::time::Duration;

use tsunagi::agent::Event;
use tsunagi::config::{AgentConfig, StoragePaths, TransportPolicy};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkName, NetworkSecret};
use tsunagi::proto::ControlMessage;
use tsunagi::{Agent, Result};

fn config(root: &std::path::Path, discovery: &SharedMemoryDiscovery) -> AgentConfig {
    AgentConfig::new(StoragePaths::under(root))
        // Loopback only: no relays, no address lookup, no port mapping.
        .with_transport(TransportPolicy::LocalOnly)
        .with_loopback_bind()
        .with_discovery(Arc::new(discovery.clone()))
        .with_discovery_interval(Duration::from_millis(200))
}

// The library never starts a runtime of its own; the binary owns it.
#[tokio::main]
async fn main() -> Result<()> {
    // The library never installs a global subscriber either.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let root = match tempfile::TempDir::new() {
        Ok(root) => root,
        Err(err) => {
            eprintln!("cannot create a temporary directory: {err}");
            return Ok(());
        }
    };
    let discovery = SharedMemoryDiscovery::new();

    let alice =
        Agent::spawn(config(&root.path().join("alice"), &discovery).with_hostname("alice")).await?;
    let bob =
        Agent::spawn(config(&root.path().join("bob"), &discovery).with_hostname("bob")).await?;

    // The end user supplies exactly these two values.
    let name = NetworkName::new("kitchen-table")?;
    let secret = NetworkSecret::generate();
    println!(
        "network secret (keep it safe): {}",
        secret.encode().as_str()
    );

    let network = alice.join_network(&name, &secret).await?;
    let same = bob.join_network(&name, &secret).await?;
    // The same name and secret always derive the same network space.
    if network != same {
        eprintln!("network derivation is not deterministic; this is a bug");
        return Ok(());
    }
    println!("network id: {network}");
    println!("alice: {}", alice.endpoint_id());
    println!("bob:   {}", bob.endpoint_id());

    let mut events = alice.subscribe();
    loop {
        match events.recv().await {
            Ok(Event::PeerConnected {
                peer,
                role,
                transport,
                rtt,
                ..
            }) => {
                println!("alice authenticated {peer} as {role:?} over {transport:?} rtt={rtt:?}");
                break;
            }
            Ok(_) => {}
            Err(err) => {
                eprintln!("event stream ended: {err}");
                break;
            }
        }
    }

    alice
        .send(
            network,
            bob.endpoint_id(),
            ControlMessage::Ping {
                seq: 1,
                payload: b"hello".to_vec(),
            },
        )
        .await?;

    while let Ok(event) = events.recv().await {
        if let Event::MessageReceived {
            peer,
            message: ControlMessage::Pong { seq, payload },
            ..
        } = event
        {
            println!(
                "pong from {peer}: seq={seq} payload={:?}",
                String::from_utf8_lossy(&payload)
            );
            break;
        }
    }

    let status = alice.status().await?;
    println!("\nalice status:");
    println!("  hostname       {}", status.hostname);
    println!("  bound sockets  {:?}", status.bound_sockets);
    println!("  cache          {:?}", status.cache_outcome);
    for net in &status.networks {
        println!("  network {} ({:?})", net.name, net.state);
        for peer in &net.peers {
            println!(
                "    peer {} hostname={:?} transport={:?} rtt={:?}",
                peer.endpoint_id, peer.hostname, peer.transport, peer.rtt
            );
            for path in &peer.paths {
                println!(
                    "      path {:?} selected={} rtt={:?}",
                    path.remote, path.is_selected, path.rtt
                );
            }
        }
        println!("    metrics {:?}", net.metrics);
    }

    alice.shutdown().await;
    bob.shutdown().await;
    Ok(())
}
