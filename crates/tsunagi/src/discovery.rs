//! Finding *candidates*, and nothing more.
//!
//! Discovery answers one question: "which iroh endpoints might currently be
//! participating in the network behind this [`DiscoveryKey`], and at which
//! addresses?". Its answers are **unverified candidates**. Membership is decided
//! later, by the control protocol handshake in [`crate::proto::handshake`].
//!
//! A discovery backend must not carry control messages between agents, must not
//! confirm authentication and must not mutate agent state directly.
//!
//! Two concerns are kept apart, and only the first one is this module's:
//!
//! * *Finding members of a network* — [`NetworkDiscovery::resolve`], keyed by
//!   the secret-derived [`DiscoveryKey`]. That is what lives here, and today
//!   it is [`StaticBootstrap`] plus a test backend; a DHT backend is future
//!   work.
//! * *Resolving the address of one iroh endpoint* — **iroh's job, not ours**.
//!   With [`crate::config::TransportPolicy::N0Defaults`] or `DirectOnly`, iroh
//!   publishes and resolves endpoint addresses through Number 0's public
//!   service, so dialling a bare [`EndpointId`] works. With `LocalOnly` there
//!   is no lookup, and a candidate must carry addresses of its own.
//!
//! No empty result ever proves a network is empty. It only means "nobody found
//! yet".
//!
//! Mainline DHT discovery is future work and is not implemented here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use iroh::{EndpointAddr, EndpointId};

use crate::error::Result;
use crate::identity::DiscoveryKey;

pub use crate::BoxFuture;

/// Where a candidate came from. Purely informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateSource {
    /// A statically configured bootstrap entry.
    Bootstrap,
    /// A discovery backend lookup.
    Discovery,
    /// An address hint restored from the disposable cache.
    Cache,
    /// An author of a signed record: somebody who belongs to this network,
    /// learned from state that reached us through anybody.
    ///
    /// It carries no address of its own — the endpoint's own discovery has
    /// to resolve it — but knowing that a member exists is what turns a
    /// star around whoever was named on the command line into a mesh.
    Member,
    /// Passed on by a member we are talking to.
    ///
    /// A candidate like any other: an introduction is not a vouching, and
    /// membership is still decided by the handshake.
    Introduced,
}

/// An unverified candidate peer.
///
/// Holding one grants nothing: the peer still has to pass the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// iroh address of the candidate, including whatever addressing info exists.
    pub addr: EndpointAddr,
    /// Where this candidate came from.
    pub source: CandidateSource,
}

impl Candidate {
    /// Creates a candidate.
    pub fn new(addr: EndpointAddr, source: CandidateSource) -> Self {
        Self { addr, source }
    }

    /// The candidate's endpoint id.
    pub fn endpoint_id(&self) -> EndpointId {
        self.addr.id
    }
}

/// A replaceable source of candidates.
///
/// Implementations must be cheap to clone behind an [`Arc`] and must never
/// block the async executor.
pub trait NetworkDiscovery: Send + Sync + std::fmt::Debug + 'static {
    /// A short name used in diagnostics.
    fn name(&self) -> &str;

    /// Publishes this agent's address under `key`.
    ///
    /// Backends that cannot publish (static bootstrap lists) return `Ok(())`.
    fn publish<'a>(&'a self, key: DiscoveryKey, addr: EndpointAddr) -> BoxFuture<'a, Result<()>>;

    /// Withdraws a previously published address.
    fn unpublish<'a>(
        &'a self,
        key: DiscoveryKey,
        endpoint: EndpointId,
    ) -> BoxFuture<'a, Result<()>>;

    /// Returns the candidates currently known for `key`.
    fn resolve<'a>(&'a self, key: DiscoveryKey) -> BoxFuture<'a, Result<Vec<Candidate>>>;
}

/// A statically configured list of bootstrap candidates.
///
/// Each entry must carry enough addressing information to be dialled, i.e. an
/// iroh endpoint id plus direct addresses or a relay URL, unless iroh's own
/// address lookup is enabled in [`crate::config::TransportPolicy`].
#[derive(Debug, Clone, Default)]
pub struct StaticBootstrap {
    entries: Vec<EndpointAddr>,
}

impl StaticBootstrap {
    /// Creates a bootstrap list.
    pub fn new(entries: impl IntoIterator<Item = EndpointAddr>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }
}

impl NetworkDiscovery for StaticBootstrap {
    fn name(&self) -> &str {
        "static-bootstrap"
    }

    fn publish<'a>(&'a self, _key: DiscoveryKey, _addr: EndpointAddr) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn unpublish<'a>(
        &'a self,
        _key: DiscoveryKey,
        _endpoint: EndpointId,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn resolve<'a>(&'a self, _key: DiscoveryKey) -> BoxFuture<'a, Result<Vec<Candidate>>> {
        let candidates: Vec<Candidate> = self
            .entries
            .iter()
            .cloned()
            .map(|addr| Candidate::new(addr, CandidateSource::Bootstrap))
            .collect();
        Box::pin(async move { Ok(candidates) })
    }
}

/// An in-process discovery backend used by tests and examples.
///
/// It stores a mapping from [`DiscoveryKey`] to endpoint addresses and nothing
/// else. It carries no messages, performs no authentication and cannot touch an
/// agent's state. Clone it to hand the same rendezvous table to several agents;
/// create a new one per test so that tests stay independent — there is no global
/// mutable state here.
#[derive(Debug, Clone, Default)]
pub struct SharedMemoryDiscovery {
    inner: Arc<Mutex<HashMap<DiscoveryKey, HashMap<EndpointId, EndpointAddr>>>>,
}

impl SharedMemoryDiscovery {
    /// Creates an empty rendezvous table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries published under `key`. Useful in tests.
    pub fn len(&self, key: &DiscoveryKey) -> usize {
        self.with_inner(|map| map.get(key).map_or(0, HashMap::len))
    }

    /// Whether nothing is published under `key`.
    pub fn is_empty(&self, key: &DiscoveryKey) -> bool {
        self.len(key) == 0
    }

    /// Removes every entry under `key`, simulating a discovery outage.
    pub fn clear(&self, key: &DiscoveryKey) {
        self.with_inner(|map| {
            map.remove(key);
        });
    }

    /// Replaces an entry with a deliberately wrong address, simulating a stale
    /// or poisoned record.
    pub fn insert_raw(&self, key: DiscoveryKey, addr: EndpointAddr) {
        self.with_inner(|map| {
            map.entry(key).or_default().insert(addr.id, addr);
        });
    }

    fn with_inner<T>(
        &self,
        f: impl FnOnce(&mut HashMap<DiscoveryKey, HashMap<EndpointId, EndpointAddr>>) -> T,
    ) -> T {
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut guard)
    }
}

impl NetworkDiscovery for SharedMemoryDiscovery {
    fn name(&self) -> &str {
        "shared-memory"
    }

    fn publish<'a>(&'a self, key: DiscoveryKey, addr: EndpointAddr) -> BoxFuture<'a, Result<()>> {
        self.with_inner(|map| {
            map.entry(key).or_default().insert(addr.id, addr);
        });
        Box::pin(async { Ok(()) })
    }

    fn unpublish<'a>(
        &'a self,
        key: DiscoveryKey,
        endpoint: EndpointId,
    ) -> BoxFuture<'a, Result<()>> {
        self.with_inner(|map| {
            if let Some(entries) = map.get_mut(&key) {
                entries.remove(&endpoint);
                if entries.is_empty() {
                    map.remove(&key);
                }
            }
        });
        Box::pin(async { Ok(()) })
    }

    fn resolve<'a>(&'a self, key: DiscoveryKey) -> BoxFuture<'a, Result<Vec<Candidate>>> {
        let candidates: Vec<Candidate> = self.with_inner(|map| {
            map.get(&key)
                .map(|entries| {
                    entries
                        .values()
                        .cloned()
                        .map(|addr| Candidate::new(addr, CandidateSource::Discovery))
                        .collect()
                })
                .unwrap_or_default()
        });
        Box::pin(async move { Ok(candidates) })
    }
}

/// Combines several backends, concatenating their candidates.
#[derive(Debug, Clone)]
pub struct CompositeDiscovery {
    backends: Vec<Arc<dyn NetworkDiscovery>>,
}

impl CompositeDiscovery {
    /// Creates a composite over the given backends.
    pub fn new(backends: impl IntoIterator<Item = Arc<dyn NetworkDiscovery>>) -> Self {
        Self {
            backends: backends.into_iter().collect(),
        }
    }
}

impl NetworkDiscovery for CompositeDiscovery {
    fn name(&self) -> &str {
        "composite"
    }

    fn publish<'a>(&'a self, key: DiscoveryKey, addr: EndpointAddr) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            for backend in &self.backends {
                // One failing backend must not stop the others.
                if let Err(err) = backend.publish(key, addr.clone()).await {
                    tracing::debug!(backend = backend.name(), %err, "publish failed");
                }
            }
            Ok(())
        })
    }

    fn unpublish<'a>(
        &'a self,
        key: DiscoveryKey,
        endpoint: EndpointId,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            for backend in &self.backends {
                if let Err(err) = backend.unpublish(key, endpoint).await {
                    tracing::debug!(backend = backend.name(), %err, "unpublish failed");
                }
            }
            Ok(())
        })
    }

    fn resolve<'a>(&'a self, key: DiscoveryKey) -> BoxFuture<'a, Result<Vec<Candidate>>> {
        Box::pin(async move {
            let mut out = Vec::new();
            for backend in &self.backends {
                match backend.resolve(key).await {
                    Ok(mut found) => out.append(&mut found),
                    Err(err) => {
                        tracing::debug!(backend = backend.name(), %err, "resolve failed");
                    }
                }
            }
            Ok(out)
        })
    }
}
