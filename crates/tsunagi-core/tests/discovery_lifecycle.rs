//! Discovery is a cancellable bootstrap job, never the network's event loop.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use iroh::{EndpointAddr, EndpointId};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tsunagi::config::DiscoveryPolicy;
use tsunagi::discovery::{BoxFuture, Candidate, NetworkDiscovery, SharedMemoryDiscovery};
use tsunagi::identity::DiscoveryKey;
use tsunagi::testing::{local_config, network, wait_for_peers, wait_until};
use tsunagi::{Agent, Result};

#[derive(Debug, Default)]
struct Counted {
    table: SharedMemoryDiscovery,
    reads: AtomicUsize,
    writes: AtomicUsize,
}

impl NetworkDiscovery for Counted {
    fn name(&self) -> &str {
        "counted"
    }
    fn publish<'a>(&'a self, key: DiscoveryKey, addr: EndpointAddr) -> BoxFuture<'a, Result<()>> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.table.publish(key, addr)
    }
    fn unpublish<'a>(&'a self, key: DiscoveryKey, id: EndpointId) -> BoxFuture<'a, Result<()>> {
        self.table.unpublish(key, id)
    }
    fn resolve<'a>(&'a self, key: DiscoveryKey) -> BoxFuture<'a, Result<Vec<Candidate>>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.table.resolve(key)
    }
}

fn policy() -> DiscoveryPolicy {
    DiscoveryPolicy {
        publish_interval: Duration::from_millis(100),
        lookup_interval: Duration::from_millis(50),
        max_lookup_interval: Duration::from_millis(100),
        reconnect_delay: Duration::from_millis(300),
        request_timeout: Duration::from_secs(2),
    }
}

#[tokio::test]
async fn connected_peers_only_publish_and_isolated_peers_resume_search() {
    let discovery = Arc::new(Counted::default());
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let config = |path: &std::path::Path| {
        local_config(path)
            .with_discovery(discovery.clone())
            .with_discovery_policy(policy())
    };
    let first = Agent::spawn(config(first_dir.path())).await.unwrap();
    let second = Agent::spawn(config(second_dir.path())).await.unwrap();
    let (name, secret) = network("discovery-lifecycle");
    let id = first.join_network(&name, &secret).await.unwrap();
    second.join_network(&name, &secret).await.unwrap();
    wait_for_peers(&first, id, 1).await;
    wait_for_peers(&second, id, 1).await;
    let reads = discovery.reads.load(Ordering::SeqCst);
    let writes = discovery.writes.load(Ordering::SeqCst);
    wait_until("publications continue while connected", || async {
        (discovery.writes.load(Ordering::SeqCst) >= writes + 6).then_some(())
    })
    .await;
    assert_eq!(discovery.reads.load(Ordering::SeqCst), reads);
    second.shutdown().await;
    wait_for_peers(&first, id, 0).await;
    wait_until("isolation resumes discovery", || async {
        (discovery.reads.load(Ordering::SeqCst) > reads).then_some(())
    })
    .await;
    first.shutdown().await;
}

#[derive(Debug)]
struct Stalled;
impl NetworkDiscovery for Stalled {
    fn name(&self) -> &str {
        "stalled"
    }
    fn publish<'a>(&'a self, _: DiscoveryKey, _: EndpointAddr) -> BoxFuture<'a, Result<()>> {
        Box::pin(std::future::pending())
    }
    fn unpublish<'a>(&'a self, _: DiscoveryKey, _: EndpointId) -> BoxFuture<'a, Result<()>> {
        Box::pin(std::future::pending())
    }
    fn resolve<'a>(&'a self, _: DiscoveryKey) -> BoxFuture<'a, Result<Vec<Candidate>>> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn stalled_discovery_does_not_block_status_or_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::spawn(local_config(dir.path()).with_discovery(Arc::new(Stalled)))
        .await
        .unwrap();
    let (name, secret) = network("stalled-discovery");
    let id = agent.join_network(&name, &secret).await.unwrap();
    // A recheck schedules work; it must not await the unreachable backend.
    agent.recheck_network(id).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), agent.network_status(id))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), agent.shutdown())
        .await
        .unwrap();
}
