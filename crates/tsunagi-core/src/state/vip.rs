//! Signed multi-writer virtual service registers and deterministic merge rules.
use crate::error::Result;
use crate::vip::{Backend, Listener, Protocol, VipConfig, VipStatus, invalid};
use crate::{Limits, NetworkId};
use iroh::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

/// A signed, independently mergeable field. A removed field keeps its tombstone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VipEntry {
    /// Network scope.
    pub network: [u8; 32],
    /// Stable service id.
    pub vip: String,
    /// Canonical field key.
    pub key: String,
    /// Encoded field value; absent means deletion.
    pub value: Option<Vec<u8>>,
    /// Lamport clock, independent of wall time.
    pub clock: u64,
    /// Persistent signing identity.
    pub author: [u8; 32],
    /// Author's durable network counter.
    pub version: u64,
    /// Ed25519 signature.
    pub signature: Vec<u8>,
}
impl VipEntry {
    fn bytes(&self) -> Vec<u8> {
        let mut e = self.clone();
        e.signature.clear();
        let mut out = b"tsunagi-vip-field/v1\0".to_vec();
        if let Ok(bytes) = postcard::to_stdvec(&e) {
            out.extend(bytes);
        }
        out
    }
    /// Verifies bounds, network and authorship before the entry is merged.
    pub fn verify(&self, network: NetworkId) -> Result<()> {
        if self.network != *network.as_bytes()
            || self.vip.len() != 32
            || hex::decode(&self.vip).is_err()
            || self.key.len() > 160
            || self.value.as_ref().is_some_and(|v| v.len() > 256)
            || self.version == 0
            || self.version > i64::MAX as u64
            || self.clock == 0
            || self.clock > i64::MAX as u64
        {
            return Err(invalid("invalid VIP field bounds or network"));
        }
        let author =
            EndpointId::from_bytes(&self.author).map_err(|_| invalid("invalid VIP author"))?;
        let raw: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| invalid("invalid VIP signature length"))?;
        author
            .verify(&self.bytes(), &Signature::from_bytes(&raw))
            .map_err(|_| invalid("invalid VIP signature"))?;
        if self.key != "deleted"
            && self.key != "name"
            && !self.key.starts_with("l/")
            && !self.key.starts_with("b/")
        {
            return Err(invalid("unknown VIP field"));
        }
        match self.key.as_str() {
            "deleted" => {
                if self.value.as_deref() != Some(&[1][..]) {
                    return Err(invalid("invalid VIP deletion tombstone"));
                }
            }
            "name" => {
                let value = self
                    .value
                    .as_ref()
                    .ok_or_else(|| invalid("VIP name cannot be absent"))?;
                let name: String =
                    postcard::from_bytes(value).map_err(|_| invalid("invalid VIP name field"))?;
                VipConfig {
                    id: self.vip.clone(),
                    name,
                    listeners: vec![],
                }
                .validate(&Limits::default())?;
            }
            key if key.starts_with("l/") => {
                let parts: Vec<_> = key.split('/').collect();
                if parts.len() != 3
                    || parts[1].parse::<Protocol>().is_err()
                    || parts[2].parse::<u16>().ok().is_none_or(|p| p == 0)
                {
                    return Err(invalid("invalid listener field key"));
                }
                if let Some(value) = &self.value {
                    let l: Listener = postcard::from_bytes(value)
                        .map_err(|_| invalid("invalid listener field"))?;
                    if !l.backends.is_empty() || key != format!("l/{}/{}", l.protocol, l.port) {
                        return Err(invalid("listener key does not match its value"));
                    }
                    VipConfig {
                        id: self.vip.clone(),
                        name: "validation".into(),
                        listeners: vec![l],
                    }
                    .validate(&Limits::default())?;
                }
            }
            key if key.starts_with("b/") => {
                let parts: Vec<_> = key.split('/').collect();
                if parts.len() != 6
                    || parts[1].parse::<Protocol>().is_err()
                    || parts[2].parse::<u16>().ok().is_none_or(|p| p == 0)
                    || parts[3].len() != 32
                    || hex::decode(parts[3]).is_err()
                    || parts[4].parse::<EndpointId>().is_err()
                    || parts[5].parse::<u16>().ok().is_none_or(|p| p == 0)
                {
                    return Err(invalid("invalid backend field key"));
                }
                if let Some(value) = &self.value {
                    let b: Backend = postcard::from_bytes(value)
                        .map_err(|_| invalid("invalid backend field"))?;
                    if b.peer != parts[4] || b.port.to_string() != parts[5] {
                        return Err(invalid("backend key does not match its value"));
                    }
                }
            }
            _ => return Err(invalid("unknown VIP field")),
        }
        Ok(())
    }
    fn rank(&self) -> (u64, [u8; 32], Vec<u8>) {
        (self.clock, self.author, self.bytes())
    }
}
/// Signed registers retained across absences, including deletion tombstones.
#[derive(Debug, Clone, Default)]
pub struct VipSet {
    entries: BTreeMap<(String, String), VipEntry>,
}
impl VipSet {
    /// Highest retained version genuinely signed by this author.
    pub fn authored_version(&self, author: EndpointId) -> u64 {
        self.entries
            .values()
            .filter(|e| e.author == *author.as_bytes())
            .map(|e| e.version)
            .max()
            .unwrap_or(0)
    }
    /// Complete independently verifiable state of one service, including tombstones.
    pub fn entries(&self, id: &str) -> Vec<VipEntry> {
        self.entries
            .values()
            .filter(|e| e.vip == id)
            .cloned()
            .collect()
    }
    /// All retained service ids, including deleted services.
    pub fn ids(&self) -> Vec<String> {
        self.entries
            .keys()
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    /// Opaque optimistic concurrency token for a whole service.
    pub fn revision(&self, id: &str) -> String {
        let mut hash = Sha256::new();
        for e in self.entries(id) {
            hash.update(e.bytes());
            hash.update(&e.signature);
        }
        hex::encode(hash.finalize())
    }
    /// Atomically verifies and merges one complete service snapshot.
    pub fn merge(
        &mut self,
        network: NetworkId,
        entries: Vec<VipEntry>,
        limits: &Limits,
    ) -> Result<bool> {
        if entries.len() > limits.max_vip_fields {
            return Err(invalid("too many VIP fields"));
        }
        let mut next = self.clone();
        for e in entries {
            e.verify(network)?;
            let key = (e.vip.clone(), e.key.clone());
            if next
                .entries
                .get(&key)
                .is_none_or(|old| e.rank() > old.rank())
            {
                next.entries.insert(key, e);
            }
        }
        let deleted: BTreeSet<_> = next
            .entries
            .values()
            .filter(|e| e.key == "deleted" && e.value.is_some())
            .map(|e| e.vip.clone())
            .collect();
        // A permanent service tombstone alone prevents every former field's replay.
        next.entries
            .retain(|(id, key), _| !deleted.contains(id) || key == "deleted");
        let ids = next.ids();
        if ids.len().saturating_sub(deleted.len()) > limits.max_vips
            || deleted.len() > limits.max_vip_tombstones
            || ids
                .iter()
                .any(|id| next.entries(id).len() > limits.max_vip_fields)
        {
            return Err(invalid(
                "VIP state capacity exceeded; deletion protection is retained",
            ));
        }
        let changed = self.entries != next.entries;
        *self = next;
        Ok(changed)
    }
    /// Materialized configuration. A service tombstone permanently retires its id.
    pub fn configs(&self) -> Vec<VipConfig> {
        self.ids()
            .into_iter()
            .filter_map(|id| self.config(&id))
            .collect()
    }
    fn config(&self, id: &str) -> Option<VipConfig> {
        let fields = self.entries(id);
        if fields
            .iter()
            .any(|e| e.key == "deleted" && e.value.is_some())
        {
            return None;
        }
        let name = fields
            .iter()
            .find(|e| e.key == "name")?
            .value
            .as_ref()
            .and_then(|v| postcard::from_bytes::<String>(v).ok())?;
        let mut listeners: Vec<Listener> = fields
            .iter()
            .filter(|e| e.key.starts_with("l/"))
            .filter_map(|e| e.value.as_ref().and_then(|v| postcard::from_bytes(v).ok()))
            .collect();
        for l in &mut listeners {
            l.backends = fields
                .iter()
                .filter(|e| {
                    e.key
                        .starts_with(&format!("b/{}/{}/{}/", l.protocol, l.port, l.id))
                })
                .filter_map(|e| e.value.as_ref().and_then(|v| postcard::from_bytes(v).ok()))
                .collect();
            l.backends.sort();
        }
        listeners.sort_by_key(|l| (l.protocol, l.port));
        Some(VipConfig {
            id: id.into(),
            name,
            listeners,
        })
    }
    /// Builds a signed patch from the user's complete, version-checked draft.
    pub fn edit(
        &self,
        network: NetworkId,
        secret: &SecretKey,
        version: u64,
        config: &VipConfig,
        expected: Option<&str>,
        limits: &Limits,
    ) -> Result<Vec<VipEntry>> {
        config.validate(limits)?;
        if let Some(revision) = expected {
            if revision != self.revision(&config.id) {
                return Err(invalid("VIP changed while editing; reload before saving"));
            }
        } else if !self.entries(&config.id).is_empty() {
            return Err(invalid("VIP id already exists"));
        }
        if self
            .entries
            .get(&(config.id.clone(), "deleted".into()))
            .is_some_and(|e| e.value.is_some())
        {
            return Err(invalid("VIP was deleted; create a new VIP"));
        }
        let before = self
            .config(&config.id)
            .map(|c| flatten(&c))
            .transpose()?
            .unwrap_or_default();
        let after = flatten(config)?;
        let keys: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
        let changes = keys
            .into_iter()
            .filter_map(|key| {
                let value = after.get(&key).cloned();
                (before.get(&key) != value.as_ref()).then_some((key, value))
            })
            .collect();
        self.sign(network, secret, version, &config.id, changes)
    }
    /// Builds a permanent service tombstone after checking the selected revision.
    pub fn delete(
        &self,
        network: NetworkId,
        secret: &SecretKey,
        version: u64,
        id: &str,
        expected: &str,
    ) -> Result<Vec<VipEntry>> {
        if self.config(id).is_none() || self.revision(id) != expected {
            return Err(invalid("VIP missing or changed while editing"));
        }
        self.sign(
            network,
            secret,
            version,
            id,
            vec![("deleted".into(), Some(vec![1]))],
        )
    }
    fn sign(
        &self,
        network: NetworkId,
        secret: &SecretKey,
        version: u64,
        id: &str,
        changes: Vec<(String, Option<Vec<u8>>)>,
    ) -> Result<Vec<VipEntry>> {
        let clock = self
            .entries
            .values()
            .map(|e| e.clock)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| invalid("VIP clock exhausted"))?;
        Ok(changes
            .into_iter()
            .map(|(key, value)| {
                let mut e = VipEntry {
                    network: *network.as_bytes(),
                    vip: id.into(),
                    key,
                    value,
                    clock,
                    author: *secret.public().as_bytes(),
                    version,
                    signature: vec![],
                };
                e.signature = secret.sign(&e.bytes()).to_bytes().to_vec();
                e
            })
            .collect())
    }
}
pub(crate) fn flatten(cfg: &VipConfig) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut fields = BTreeMap::new();
    fields.insert(
        "name".into(),
        postcard::to_stdvec(&cfg.name).map_err(|e| invalid(e.to_string()))?,
    );
    for l in &cfg.listeners {
        let mut settings = l.clone();
        settings.backends.clear();
        fields.insert(
            format!("l/{}/{}", l.protocol, l.port),
            postcard::to_stdvec(&settings).map_err(|e| invalid(e.to_string()))?,
        );
        for b in &l.backends {
            fields.insert(
                format!("b/{}/{}/{}/{}/{}", l.protocol, l.port, l.id, b.peer, b.port),
                postcard::to_stdvec(b).map_err(|e| invalid(e.to_string()))?,
            );
        }
    }
    Ok(fields)
}
impl VipSet {
    /// Allocates internal addresses deterministically against durable node claims.
    pub(crate) fn views(
        &self,
        range: Option<crate::state::Ipv4Range>,
        mut taken: std::collections::HashSet<Ipv4Addr>,
        hostnames: &BTreeSet<String>,
        limits: &Limits,
    ) -> Vec<VipStatus> {
        let mut names = hostnames.clone();
        let mut result = Vec::new();
        for config in self.configs() {
            let mut error = config.validate(limits).err().map(|e| e.to_string());
            if !names.insert(config.name.clone()) {
                error = Some("name conflicts with another VIP or node".into());
            }
            let address = range.and_then(|r| {
                let usable = crate::state::allocator::usable_addresses(r);
                if usable == 0 {
                    return None;
                }
                let digest = Sha256::digest(config.id.as_bytes());
                let seed = u64::from_be_bytes([
                    digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
                    digest[7],
                ]);
                let bits = 32 - u32::from(r.prefix_len);
                let mask = if bits == 32 { 0 } else { u32::MAX << bits };
                (0..usable).find_map(|step| {
                    let offset = (seed.wrapping_add(step) % usable + 1) as u32;
                    let ip = Ipv4Addr::from((u32::from(r.base) & mask) | offset);
                    taken.insert(ip).then_some(ip)
                })
            });
            if address.is_none() {
                error = Some("no free overlay address".into());
            }
            result.push(VipStatus {
                revision: self.revision(&config.id),
                config,
                address,
                error,
                listeners: vec![],
            });
        }
        result
    }
}
