//! Mainline BEP44 rendezvous. Slots are a changing sample, not a membership list.

use ::mainline::{Dht, MutableItem, SigningKey, async_dht::AsyncDht};
use futures_lite::StreamExt;
use iroh::{EndpointAddr, EndpointId};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinSet;
use tokio::time::timeout;
use zeroize::Zeroizing;

use super::{BoxFuture, Candidate, CandidateSource, NetworkDiscovery};
use crate::config::{
    DHT_CLOCK_SKEW, DHT_MAX_ADDRS, DHT_MAX_RELAY_LEN, DHT_MAX_VALUE, DHT_RECORD_TTL, DHT_SLOTS,
};
use crate::error::{Error, Result};
use crate::identity::{DiscoveryKey, NetworkKeys};

const QUERY_TIMEOUT: Duration = Duration::from_secs(8);
const MAGIC: &[u8; 5] = b"TSND\x01";

/// One lazily started Mainline client, shared by all networks on one agent.
/// No socket is opened until an active network publishes or looks up candidates.
/// Agent shutdown closes this client and all its clones; a new agent needs a new client.
#[derive(Debug, Clone, Default)]
pub struct MainlineDiscovery {
    client: Arc<AsyncMutex<ClientState>>,
    allow_loopback: bool,
}

#[derive(Debug, Default)]
enum ClientState {
    #[default]
    Pending,
    Ready(AsyncDht),
    Stopped,
}

impl MainlineDiscovery {
    /// Uses a caller-supplied Mainline node instead of public bootstrap defaults.
    pub fn from_dht(dht: Dht) -> Self {
        Self {
            client: Arc::new(AsyncMutex::new(ClientState::Ready(dht.as_async()))),
            allow_loopback: false,
        }
    }

    /// Creates a loopback-only client for a local Mainline Testnet.
    #[cfg(feature = "testing")]
    pub fn local_testnet(bootstrap: &[String]) -> Result<Self> {
        // Reject anything that could resolve or send outside loopback.
        if bootstrap.is_empty()
            || bootstrap.iter().any(|s| {
                s.parse::<SocketAddr>()
                    .map_or(true, |a| !a.ip().is_loopback())
            })
        {
            return Err(Error::Discovery(
                "test bootstrap must contain loopback sockets".into(),
            ));
        }
        let dht = Dht::builder()
            .bootstrap(bootstrap)
            .bind_address(Ipv4Addr::LOCALHOST)
            .port(0)
            .request_timeout(Duration::from_millis(200))
            .build()
            .map_err(|_| Error::Discovery("cannot bind local DHT".into()))?;
        Ok(Self {
            allow_loopback: true,
            ..Self::from_dht(dht)
        })
    }

    /// Binds this client's rendezvous backend to one network's independent keys.
    pub fn for_network(&self, keys: &NetworkKeys) -> Arc<dyn NetworkDiscovery> {
        Arc::new(NetworkDht {
            client: self.clone(),
            key: keys.discovery_key(),
            seed: Zeroizing::new(*keys.dht_write_key()),
            observed: Mutex::new(VecDeque::new()),
        })
    }

    async fn client(&self) -> Result<AsyncDht> {
        let mut client = self.client.lock().await;
        match &*client {
            ClientState::Ready(dht) => return Ok(dht.clone()),
            ClientState::Stopped => return Err(Error::Discovery("DHT client is stopped".into())),
            ClientState::Pending => {}
        }
        // Construction may resolve bootstrap hostnames. Keep it off Tokio's
        // executor; a construction failure is retried on the next operation.
        let dht = tokio::task::spawn_blocking(|| Dht::builder().port(0).build())
            .await
            .map_err(|_| Error::Discovery("DHT startup task failed".into()))?
            .map(Dht::as_async)
            .map_err(|_| Error::Discovery("cannot start DHT client".into()))?;
        *client = ClientState::Ready(dht.clone());
        Ok(dht)
    }

    pub(crate) async fn shutdown(&self) {
        *self.client.lock().await = ClientState::Stopped;
    }
}

struct NetworkDht {
    client: MainlineDiscovery,
    key: DiscoveryKey,
    seed: Zeroizing<[u8; 32]>,
    // Records encountered while publishing. Only an explicit lookup consumes
    // these hints: publication never causes dials on a connected network.
    observed: Mutex<VecDeque<Vec<u8>>>,
}

impl std::fmt::Debug for NetworkDht {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkDht(<redacted>)")
    }
}

fn salt(slot: u8) -> Vec<u8> {
    let mut salt = b"tsunagi-rendezvous-v1".to_vec();
    salt.push(slot);
    salt
}

fn slots_for(id: EndpointId) -> [u8; 2] {
    let hash = Sha256::digest(id.as_bytes());
    let first = hash[0] % DHT_SLOTS;
    [first, (first + 1 + hash[1] % (DHT_SLOTS - 1)) % DHT_SLOTS]
}

fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Discovery("system clock predates Unix epoch".into()))
}

impl NetworkDht {
    async fn publish_slot(&self, dht: &AsyncDht, slot: u8, value: &[u8]) -> Result<()> {
        let salt = salt(slot);
        let signer = SigningKey::from_bytes(&self.seed);
        let public = signer.verifying_key().to_bytes();
        for attempt in 0..3 {
            let recent = timeout(
                QUERY_TIMEOUT,
                dht.get_mutable_most_recent(&public, Some(&salt)),
            )
            .await
            .map_err(|_| Error::Discovery("DHT read timed out".into()))?;
            if let Some(item) = &recent
                && item.value().len() <= DHT_MAX_VALUE
                && let Ok(mut observed) = self.observed.lock()
            {
                if observed.len() == DHT_SLOTS as usize {
                    observed.pop_front();
                }
                observed.push_back(item.value().to_vec());
            }
            let seq = recent
                .as_ref()
                .map_or(0, MutableItem::seq)
                .checked_add(1)
                .ok_or_else(|| Error::Discovery("DHT sequence exhausted".into()))?;
            let item = MutableItem::new(signer.clone(), value, seq, Some(&salt));
            match timeout(
                QUERY_TIMEOUT,
                dht.put_mutable(item, recent.as_ref().map(MutableItem::seq)),
            )
            .await
            {
                Ok(Ok(outcome)) if outcome.stored_at > 0 => return Ok(()),
                _ if attempt < 2 => {
                    // CAS is per storage node, not a global lock. Read again on
                    // conflicts; another writer's entry is an acceptable sample.
                    tokio::time::sleep(Duration::from_millis(rand::random_range(30..150))).await;
                }
                _ => break,
            }
        }
        Err(Error::Discovery(
            "DHT publication was not acknowledged".into(),
        ))
    }
}

impl NetworkDiscovery for NetworkDht {
    fn name(&self) -> &str {
        "mainline"
    }

    fn publish<'a>(&'a self, key: DiscoveryKey, addr: EndpointAddr) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if key != self.key {
                return Err(Error::Discovery("wrong rendezvous network".into()));
            }
            let value = encode_record(&addr, now()?, self.client.allow_loopback)?;
            let dht = self.client.client().await?;
            let [first, second] = slots_for(addr.id);
            let (a, b) = tokio::join!(
                self.publish_slot(&dht, first, &value),
                self.publish_slot(&dht, second, &value)
            );
            a.and(b)
        })
    }

    fn unpublish<'a>(&'a self, _: DiscoveryKey, _: EndpointId) -> BoxFuture<'a, Result<()>> {
        // Stopping publication lets freshness expire. Deleting a shared slot
        // could erase a different writer, and BEP44 has no delete operation.
        Box::pin(async { Ok(()) })
    }

    fn resolve<'a>(&'a self, key: DiscoveryKey) -> BoxFuture<'a, Result<Vec<Candidate>>> {
        Box::pin(async move {
            let (tx, mut rx) = mpsc::channel(DHT_SLOTS as usize);
            let collect = async move {
                let mut found = Vec::new();
                while let Some(candidate) = rx.recv().await {
                    found.push(candidate);
                }
                found
            };
            let (result, found) = tokio::join!(self.resolve_into(key, tx), collect);
            result?;
            Ok(found)
        })
    }

    fn resolve_into<'a>(
        &'a self,
        key: DiscoveryKey,
        candidates: mpsc::Sender<Candidate>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if key != self.key {
                return Err(Error::Discovery("wrong rendezvous network".into()));
            }
            let dht = self.client.client().await?;
            let public = SigningKey::from_bytes(&self.seed)
                .verifying_key()
                .to_bytes();
            let observed = self
                .observed
                .lock()
                .map(|mut values| std::mem::take(&mut *values))
                .unwrap_or_default();
            let mut seen = HashSet::new();
            for value in observed {
                if let Some(addr) = decode_record(&value, now()?, self.client.allow_loopback)
                    && seen.insert(addr.id)
                    && candidates
                        .send(Candidate::new(addr, CandidateSource::Discovery))
                        .await
                        .is_err()
                {
                    return Ok(());
                }
            }
            let mut slots: Vec<_> = (0..DHT_SLOTS).collect();
            for i in (1..slots.len()).rev() {
                slots.swap(i, rand::random_range(0..=i));
            }
            let mut queries = JoinSet::new();
            loop {
                if seen.len() >= DHT_SLOTS as usize {
                    break;
                }
                while queries.len() < 4 {
                    let Some(slot) = slots.pop() else {
                        break;
                    };
                    let dht = dht.clone();
                    let allow_loopback = self.client.allow_loopback;
                    queries.spawn(async move {
                        timeout(QUERY_TIMEOUT, async move {
                            let salt = salt(slot);
                            let target = MutableItem::target_from_key(&public, Some(&salt));
                            let mut items = dht.get_mutable(&public, Some(&salt), None);
                            while let Some(item) = items.next().await {
                                // Mainline verifies the signature; also bind the
                                // returned item to the key and slot we requested.
                                if item.key() != &public || item.target() != &target {
                                    continue;
                                }
                                if let Some(addr) =
                                    decode_record(item.value(), now().ok()?, allow_loopback)
                                {
                                    return Some(addr);
                                }
                            }
                            None
                        })
                        .await
                        .ok()
                        .flatten()
                    });
                }
                let Some(result) = queries.join_next().await else {
                    break;
                };
                if let Ok(Some(addr)) = result
                    && seen.insert(addr.id)
                    && candidates
                        .send(Candidate::new(addr, CandidateSource::Discovery))
                        .await
                        .is_err()
                {
                    break;
                }
            }
            Ok(())
        })
    }
}

fn usable(addr: &SocketAddr, allow_loopback: bool) -> bool {
    addr.port() != 0
        && !addr.ip().is_unspecified()
        && !addr.ip().is_multicast()
        && (allow_loopback || !addr.ip().is_loopback())
        && match addr.ip() {
            IpAddr::V4(ip) => !ip.is_broadcast() && !ip.is_link_local(),
            IpAddr::V6(ip) => !ip.is_unicast_link_local(),
        }
}

fn encode_record(addr: &EndpointAddr, timestamp: u64, allow_loopback: bool) -> Result<Vec<u8>> {
    let ips: Vec<_> = addr
        .ip_addrs()
        .filter(|ip| usable(ip, allow_loopback))
        .take(DHT_MAX_ADDRS)
        .collect();
    let relay = addr
        .relay_urls()
        .next()
        .map(ToString::to_string)
        .unwrap_or_default();
    if relay.len() > DHT_MAX_RELAY_LEN || (ips.is_empty() && relay.is_empty()) {
        return Err(Error::Discovery("no encodable endpoint address yet".into()));
    }
    let mut bytes = Vec::with_capacity(DHT_MAX_VALUE);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(addr.id.as_bytes());
    bytes.extend_from_slice(&(relay.len() as u16).to_be_bytes());
    bytes.extend_from_slice(relay.as_bytes());
    bytes.push(ips.len() as u8);
    for ip in ips {
        match ip.ip() {
            IpAddr::V4(v) => {
                bytes.push(4);
                bytes.extend_from_slice(&v.octets());
            }
            IpAddr::V6(v) => {
                bytes.push(6);
                bytes.extend_from_slice(&v.octets());
            }
        }
        bytes.extend_from_slice(&ip.port().to_be_bytes());
    }
    if bytes.len() > DHT_MAX_VALUE {
        return Err(Error::Discovery("DHT record too large".into()));
    }
    Ok(bytes)
}

fn take<'a>(input: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, rest) = input.split_at_checked(n)?;
    *input = rest;
    Some(head)
}

fn decode_record(mut bytes: &[u8], now: u64, allow_loopback: bool) -> Option<EndpointAddr> {
    if bytes.len() > DHT_MAX_VALUE || take(&mut bytes, MAGIC.len())? != MAGIC {
        return None;
    }
    let timestamp = u64::from_be_bytes(take(&mut bytes, 8)?.try_into().ok()?);
    if timestamp > now.saturating_add(DHT_CLOCK_SKEW.as_secs())
        || now.saturating_sub(timestamp) >= DHT_RECORD_TTL.as_secs()
    {
        return None;
    }
    let id = EndpointId::from_bytes(take(&mut bytes, 32)?.try_into().ok()?).ok()?;
    let mut addr = EndpointAddr::new(id);
    let len = u16::from_be_bytes(take(&mut bytes, 2)?.try_into().ok()?) as usize;
    if len > DHT_MAX_RELAY_LEN {
        return None;
    }
    let relay = std::str::from_utf8(take(&mut bytes, len)?).ok()?;
    if !relay.is_empty() {
        addr = addr.with_relay_url(relay.parse().ok()?);
    }
    let count = *take(&mut bytes, 1)?.first()? as usize;
    if count > DHT_MAX_ADDRS {
        return None;
    }
    for _ in 0..count {
        let ip = match *take(&mut bytes, 1)?.first()? {
            4 => IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(take(&mut bytes, 4)?).ok()?,
            )),
            6 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(take(&mut bytes, 16)?).ok()?,
            )),
            _ => return None,
        };
        let port = u16::from_be_bytes(take(&mut bytes, 2)?.try_into().ok()?);
        let socket = SocketAddr::new(ip, port);
        if usable(&socket, allow_loopback) {
            addr = addr.with_ip_addr(socket);
        }
    }
    (bytes.is_empty() && !addr.addrs.is_empty()).then_some(addr)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::testing::network;

    fn address() -> EndpointAddr {
        EndpointAddr::new(iroh::SecretKey::generate().public())
            .with_ip_addr("127.0.0.1:12345".parse().unwrap())
    }

    #[test]
    fn records_reject_expiration_future_dates_truncation_and_oversize() {
        let addr = address();
        let bytes = encode_record(&addr, 1_000, true).unwrap();
        assert_eq!(decode_record(&bytes, 1_100, true).unwrap(), addr);
        assert!(decode_record(&bytes, 1_901, true).is_none());
        assert!(decode_record(&bytes, 100, true).is_none());
        for n in 0..bytes.len() {
            assert!(decode_record(&bytes[..n], 1_100, true).is_none());
        }
        assert!(decode_record(&vec![0; DHT_MAX_VALUE + 1], 1_100, true).is_none());
        assert!(encode_record(&addr, 1_000, false).is_err());
        assert!(decode_record(&bytes, 1_100, false).is_none());
    }

    #[tokio::test]
    async fn a_stopped_custom_client_never_falls_back_to_public_bootstrap() {
        let net = mainline::Testnet::builder(3).build().unwrap();
        let client = MainlineDiscovery::local_testnet(&net.bootstrap).unwrap();
        let (name, secret) = network("mainline-shutdown");
        let keys = NetworkKeys::derive(&name, &secret);
        let backend = client.for_network(&keys);
        client.shutdown().await;
        assert!(backend.resolve(keys.discovery_key()).await.is_err());
    }

    #[tokio::test]
    async fn concurrent_writers_share_slots_and_other_secrets_find_nothing() {
        let net = mainline::Testnet::builder(5).build().unwrap();
        let client_a = MainlineDiscovery::local_testnet(&net.bootstrap).unwrap();
        let client_b = MainlineDiscovery::local_testnet(&net.bootstrap).unwrap();
        let (name, secret) = network("mainline-slots");
        let keys = NetworkKeys::derive(&name, &secret);
        let a = client_a.for_network(&keys);
        let b = client_b.for_network(&keys);
        let first = address();
        let second = loop {
            let next = address();
            if slots_for(next.id) == slots_for(first.id) {
                break next;
            }
        };
        let key = keys.discovery_key();
        let (ra, rb) = tokio::join!(
            a.publish(key, first.clone()),
            b.publish(key, second.clone())
        );
        assert!(ra.is_ok() || rb.is_ok());
        let (found_a, found_b) = tokio::join!(a.resolve(key), b.resolve(key));
        let found_a = found_a.unwrap();
        let found_b = found_b.unwrap();
        assert!(
            found_a.iter().any(|c| c.addr == second) || found_b.iter().any(|c| c.addr == first),
            "at least one writer must discover the other despite colliding in both slots"
        );
        assert!(
            found_a
                .iter()
                .chain(&found_b)
                .all(|c| c.addr == first || c.addr == second)
        );
        let other = NetworkKeys::derive(&name, &crate::identity::NetworkSecret::generate());
        assert!(
            client_a
                .for_network(&other)
                .resolve(other.discovery_key())
                .await
                .unwrap()
                .is_empty()
        );
        // Restarting the publisher must read seq from DHT instead of starting at 1.
        let restarted = client_a.for_network(&keys);
        restarted.publish(key, first.clone()).await.unwrap();
        assert!(
            b.resolve(key)
                .await
                .unwrap()
                .iter()
                .any(|c| c.addr == first)
        );
    }
}
