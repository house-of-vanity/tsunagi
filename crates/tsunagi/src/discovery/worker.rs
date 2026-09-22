//! Per-network discovery tasks. Dropping the owner cancels all backend futures.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};

use super::{Candidate, NetworkDiscovery};
use crate::config::DiscoveryPolicy;
use crate::identity::DiscoveryKey;
use crate::net::EndpointAdapter;

pub(crate) struct DiscoveryWorker {
    connected: watch::Sender<Connectivity>,
    tasks: JoinSet<()>,
    backend: Arc<dyn NetworkDiscovery>,
    key: DiscoveryKey,
    endpoint: iroh::EndpointId,
}

#[derive(Clone, Copy)]
enum Connectivity {
    Initial,
    Connected,
    Isolated(Instant),
}

impl DiscoveryWorker {
    pub(crate) fn spawn(
        backend: Arc<dyn NetworkDiscovery>,
        key: DiscoveryKey,
        adapter: EndpointAdapter,
        policy: DiscoveryPolicy,
        address_check: Duration,
        candidates: mpsc::Sender<Candidate>,
    ) -> Self {
        let (connected, receiver) = watch::channel(Connectivity::Initial);
        let mut tasks = JoinSet::new();
        tasks.spawn(publish_loop(
            backend.clone(),
            key,
            adapter.clone(),
            policy.clone(),
            address_check,
        ));
        tasks.spawn(lookup_loop(
            backend.clone(),
            key,
            policy,
            receiver,
            candidates,
        ));
        Self {
            connected,
            tasks,
            backend,
            key,
            endpoint: adapter.endpoint_id(),
        }
    }

    pub(crate) fn set_connected(&self, connected: bool) {
        self.connected.send_if_modified(|current| {
            if matches!(*current, Connectivity::Connected) == connected {
                return false;
            }
            *current = if connected {
                Connectivity::Connected
            } else {
                Connectivity::Isolated(Instant::now())
            };
            true
        });
    }

    pub(crate) async fn stop(mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        // BEP44 has no deletion. Memory/static backends can withdraw promptly;
        // an unresponsive backend must not extend agent shutdown.
        let _ = timeout(
            Duration::from_millis(250),
            self.backend.unpublish(self.key, self.endpoint),
        )
        .await;
    }
}

fn jitter(delay: Duration) -> Duration {
    delay
        .mul_f64(0.8 + 0.4 * rand::random::<f64>())
        .max(Duration::from_millis(10))
}

async fn publish_loop(
    backend: Arc<dyn NetworkDiscovery>,
    key: DiscoveryKey,
    adapter: EndpointAdapter,
    policy: DiscoveryPolicy,
    address_check: Duration,
) {
    let mut previous = None;
    let mut due = Instant::now();
    let mut ticker = tokio::time::interval(address_check.max(Duration::from_millis(10)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let mut addr = adapter.addr();
        addr.addrs.extend(adapter.loopback_addr().addrs);
        if previous.as_ref() != Some(&addr) {
            previous = Some(addr.clone());
            due = Instant::now();
        }
        if Instant::now() < due {
            continue;
        }
        let result = timeout(policy.request_timeout, backend.publish(key, addr.clone())).await;
        match result {
            Ok(Ok(())) => {
                due = Instant::now() + jitter(policy.publish_interval);
            }
            result => {
                tracing::debug!(?result, "discovery publication failed; will retry");
                due = Instant::now() + jitter(policy.lookup_interval);
            }
        }
    }
}

async fn lookup_loop(
    backend: Arc<dyn NetworkDiscovery>,
    key: DiscoveryKey,
    policy: DiscoveryPolicy,
    mut connected: watch::Receiver<Connectivity>,
    candidates: mpsc::Sender<Candidate>,
) {
    let mut last_isolation = None;
    let mut due = Instant::now();
    let mut delay = policy.lookup_interval;
    loop {
        let state = *connected.borrow_and_update();
        if matches!(state, Connectivity::Connected) {
            if connected.changed().await.is_err() {
                break;
            }
            continue;
        }
        if let Connectivity::Isolated(since) = state
            && last_isolation != Some(since)
        {
            // Preserve the transition time even if a rapid reconnect/disconnect
            // overwrote a watch value before this task had a chance to run.
            due = since + policy.reconnect_delay;
            delay = policy.lookup_interval;
            last_isolation = Some(since);
        }
        tokio::select! {
            biased;
            changed = connected.changed() => {
                if changed.is_err() { break; }
                continue;
            }
            _ = tokio::time::sleep_until(due) => {}
        }
        tokio::select! {
            biased;
            changed = connected.changed() => {
                if changed.is_err() { break; }
                continue;
            }
            result = timeout(policy.request_timeout, backend.resolve_into(key, candidates.clone())) => {
                if !matches!(result, Ok(Ok(()))) {
                    tracing::debug!(?result, "discovery lookup failed; will retry");
                }
            }
        }
        due = Instant::now() + jitter(delay);
        delay = delay.saturating_mul(2).min(policy.max_lookup_interval);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::Result;
    use crate::discovery::BoxFuture;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct Reads(AtomicUsize);
    impl NetworkDiscovery for Reads {
        fn name(&self) -> &str {
            "reads"
        }
        fn publish<'a>(
            &'a self,
            _: DiscoveryKey,
            _: iroh::EndpointAddr,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn unpublish<'a>(
            &'a self,
            _: DiscoveryKey,
            _: iroh::EndpointId,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn resolve<'a>(&'a self, _: DiscoveryKey) -> BoxFuture<'a, Result<Vec<Candidate>>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_requires_a_full_minute_and_reconnection_restarts_that_minute() {
        let reads = Arc::new(Reads::default());
        let (tx, rx) = watch::channel(Connectivity::Connected);
        let (candidates, _receiver) = mpsc::channel(16);
        let mut tasks = JoinSet::new();
        tasks.spawn(lookup_loop(
            reads.clone(),
            DiscoveryKey::from_bytes([0; 32]),
            DiscoveryPolicy::default(),
            rx,
            candidates,
        ));
        tokio::task::yield_now().await;
        tx.send(Connectivity::Isolated(Instant::now())).unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(59)).await;
        tokio::task::yield_now().await;
        assert_eq!(reads.0.load(Ordering::SeqCst), 0);
        tx.send(Connectivity::Connected).unwrap();
        tx.send(Connectivity::Isolated(Instant::now())).unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(59)).await;
        tokio::task::yield_now().await;
        assert_eq!(reads.0.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(reads.0.load(Ordering::SeqCst), 1);
        tx.send(Connectivity::Connected).unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(600)).await;
        tokio::task::yield_now().await;
        assert_eq!(reads.0.load(Ordering::SeqCst), 1);
    }
}
