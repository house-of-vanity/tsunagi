//! Shared helpers for the integration tests.
//!
//! Every test uses real iroh endpoints on loopback, its own temporary SQLite
//! files and independent agent instances. Only discovery is substituted; iroh,
//! the handshake, message passing and persistent storage are not.
//!
//! Synchronisation is always "wait for a specific event or condition, under one
//! overall deadline", never a fixed multi-second sleep.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::TempDir;
use tokio::sync::broadcast::error::RecvError;
use tsunagi::agent::Event;
use tsunagi::config::{AgentConfig, StoragePaths, TransportPolicy};
use tsunagi::discovery::SharedMemoryDiscovery;
use tsunagi::identity::{NetworkName, NetworkSecret};
use tsunagi::{Agent, Result};

/// Installs a tracing subscriber when `TSUNAGI_TEST_LOG` is set.
///
/// The library never installs a global subscriber itself; tests opt in.
pub fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if let Ok(filter) = std::env::var("TSUNAGI_TEST_LOG") {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
                .with_writer(std::io::stderr)
                .try_init();
        }
    });
}

/// Overall deadline for anything a test waits on.
pub const DEADLINE: Duration = Duration::from_secs(30);

/// How often condition polling re-checks. Never used as the primary sync.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Builds a fully local configuration rooted at `dir`.
///
/// Loopback binding with a dynamic port, no relay, no address lookup and no
/// port mapping, so the suite needs neither the internet nor privileges.
/// Timeouts are shortened so that failure paths finish quickly.
pub fn local_config(dir: &Path) -> AgentConfig {
    let limits = tsunagi::Limits {
        dial_timeout: Duration::from_millis(1500),
        handshake_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    AgentConfig::new(StoragePaths::under(dir))
        .with_transport(TransportPolicy::LocalOnly)
        .with_loopback_bind()
        .with_discovery_interval(Duration::from_millis(150))
        .with_limits(limits)
}

/// Builds a local configuration wired to a shared in-memory discovery table.
pub fn config_with(dir: &Path, discovery: &SharedMemoryDiscovery) -> AgentConfig {
    local_config(dir).with_discovery(Arc::new(discovery.clone()))
}

/// A temporary directory plus the agent running on it.
pub struct TestAgent {
    pub dir: TempDir,
    pub agent: Agent,
}

impl TestAgent {
    /// Starts an agent on a fresh temporary directory.
    pub async fn spawn(discovery: &SharedMemoryDiscovery) -> Result<Self> {
        init_tracing();
        let dir = TempDir::new().expect("temp dir");
        let agent = Agent::spawn(config_with(dir.path(), discovery)).await?;
        Ok(Self { dir, agent })
    }

    /// Starts an agent with a caller-supplied configuration on a fresh dir.
    pub async fn spawn_with(
        build: impl FnOnce(AgentConfig) -> AgentConfig,
        discovery: &SharedMemoryDiscovery,
    ) -> Result<Self> {
        init_tracing();
        let dir = TempDir::new().expect("temp dir");
        let agent = Agent::spawn(build(config_with(dir.path(), discovery))).await?;
        Ok(Self { dir, agent })
    }

    /// Stops the agent and returns the directory so it can be reopened.
    pub async fn stop(self) -> TempDir {
        self.agent.shutdown().await;
        self.dir
    }
}

/// A network name and a fresh high-entropy secret.
pub fn network(name: &str) -> (NetworkName, NetworkSecret) {
    (
        NetworkName::new(name).expect("valid network name"),
        NetworkSecret::generate(),
    )
}

/// Waits for an event matching `predicate`, under the global deadline.
pub async fn wait_event<T>(
    rx: &mut tokio::sync::broadcast::Receiver<Event>,
    predicate: impl Fn(&Event) -> Option<T>,
) -> T {
    let deadline = Instant::now() + DEADLINE;
    let mut seen: Vec<String> = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        assert!(!remaining.is_zero(), "timed out waiting for an event");

        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(event)) => {
                if let Some(value) = predicate(&event) {
                    return value;
                }
                if seen.len() < 12 {
                    let label = format!("{event:?}");
                    seen.push(label.chars().take(70).collect());
                }
            }
            Ok(Err(RecvError::Lagged(skipped))) => {
                panic!("event subscriber lagged, missed {skipped} events; first seen: {seen:#?}");
            }
            Ok(Err(RecvError::Closed)) => panic!("event channel closed while waiting"),
            Err(_) => panic!("timed out waiting for an event"),
        }
    }
}

/// Polls an async condition until it returns `Some`, under the global deadline.
pub async fn wait_until<T, F, Fut>(what: &str, mut probe: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = Instant::now() + DEADLINE;
    loop {
        if let Some(value) = probe().await {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for condition: {what}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Lets a few discovery rounds pass.
///
/// Only ever used before asserting that something did **not** happen; waiting
/// for success always goes through [`wait_event`] or [`wait_until`].
pub async fn settle() {
    tokio::time::sleep(Duration::from_millis(900)).await;
}

/// Waits until `agent` has `count` authenticated peers in `network`.
pub async fn wait_for_peers(
    agent: &Agent,
    network: tsunagi::NetworkId,
    count: usize,
) -> Vec<iroh::EndpointId> {
    wait_until(&format!("{count} peers in {network}"), || async move {
        let status = agent.network_status(network).await.ok()?;
        if status.peers.len() >= count {
            Some(status.connected_peers())
        } else {
            None
        }
    })
    .await
}
