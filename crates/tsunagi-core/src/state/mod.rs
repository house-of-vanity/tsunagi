//! Signed state that outlives a session.
//!
//! This is the first slice of the model in `docs/sync-model.md`: **each author
//! signs its own records, and replicas merge them**. It exists because some
//! facts have to survive a participant being away — an overlay address it
//! claimed months ago, for instance — and a fact that only lives in a live
//! session cannot do that.
//!
//! # Why there is no vote
//!
//! Anyone who knows the network secret can mint as many identities as they
//! like, so a majority proves nothing; the threat model says as much. A quorum
//! would also stall whenever a single participant is online and diverge across
//! a partition. Instead:
//!
//! * an author signs only its **own** records, so nobody needs anybody's
//!   permission to state a fact about itself;
//! * merging is **deterministic**, so every replica that has seen the same
//!   records reaches the same conclusion without exchanging opinions;
//! * a genuine clash — two authors claiming one address at the same moment —
//!   is resolved by a rule both sides compute identically, and the loser
//!   simply picks again with a higher version.
//!
//! # What a record is
//!
//! One record per author per network, holding that author's **complete
//! current** statement rather than a delta, exactly as the model requires: a
//! replica that has the record needs nothing else to interpret it, and
//! recovery never depends on replaying a chain from the beginning.
//!
//! # What this slice does not do yet
//!
//! Compaction, revocation of a whole author, and snapshots covering more than
//! one record type. See `docs/sync-model.md` for the shape those take.

pub mod allocator;

use std::collections::HashMap;
use std::net::Ipv4Addr;

use iroh::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};

use crate::identity::NetworkId;

/// Why an IPv4 range could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct RangeError(pub String);

/// An IPv4 range the overlay allocates addresses from.
///
/// One range per network. An agent proposes one through
/// [`crate::config::AgentConfig::overlay_ipv4_range`], but a network that has
/// already settled on another wins: see [`StateSet::agreed_range`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4Range {
    /// Base address of the range.
    pub base: Ipv4Addr,
    /// Prefix length, at most 30 so there is room for hosts.
    pub prefix_len: u8,
}

impl Ipv4Range {
    /// Builds a range, rejecting one with no room for hosts.
    pub fn new(base: Ipv4Addr, prefix_len: u8) -> Result<Self, RangeError> {
        if prefix_len > 30 {
            return Err(RangeError(format!(
                "a /{prefix_len} has no room for hosts; use /30 or larger"
            )));
        }
        Ok(Self { base, prefix_len })
    }

    /// Whether an address falls inside the range.
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        let host_bits = 32 - u32::from(self.prefix_len);
        let mask = if host_bits >= 32 {
            0
        } else {
            u32::MAX << host_bits
        };
        u32::from(address) & mask == u32::from(self.base) & mask
    }
}

impl std::fmt::Display for Ipv4Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.base, self.prefix_len)
    }
}

impl std::str::FromStr for Ipv4Range {
    type Err = RangeError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (base, prefix) = text.split_once('/').ok_or_else(|| {
            RangeError(format!(
                "`{text}` is not an address with a prefix, for example 10.77.0.0/16"
            ))
        })?;
        let base = base
            .parse()
            .map_err(|err| RangeError(format!("`{base}` is not an IPv4 address: {err}")))?;
        let prefix_len = prefix
            .parse()
            .map_err(|err| RangeError(format!("`{prefix}` is not a prefix length: {err}")))?;
        Self::new(base, prefix_len)
    }
}

/// The IPv4 overlay range used unless something else is configured or agreed.
///
/// A small, specific `/24`: memorable, and far less likely to overlap a
/// network the machine is already on than taking a whole `/8` or `/10` would
/// be. Because addresses are allocated rather than derived, 254 of them is
/// plenty for the size of network this is for.
pub const DEFAULT_IPV4_RANGE: Ipv4Range = Ipv4Range {
    base: Ipv4Addr::new(10, 13, 37, 0),
    prefix_len: 24,
};

/// A range derived from a network's own identity.
///
/// One agent has one interface, so two of its networks cannot both use the
/// configured range. The second needs another one — and it cannot be picked
/// locally, because every member has to arrive at the same answer without
/// being told. So it comes from the network id, which every member already
/// has and nobody can choose: the same network derives the same range on
/// every device.
///
/// Inside 10/8 like the default, and never equal to it, so the first
/// network keeps what it has always had.
pub fn derived_ipv4_range(network: NetworkId) -> Ipv4Range {
    let bytes = network.as_bytes();
    let second = bytes[0];
    let third = bytes[1];
    let candidate = Ipv4Addr::new(10, second, third, 0);
    // The default is somebody's already. One step along is still derived
    // from the id and still the same everywhere.
    let base = if candidate == DEFAULT_IPV4_RANGE.base {
        Ipv4Addr::new(10, second, third.wrapping_add(1), 0)
    } else {
        candidate
    };
    Ipv4Range {
        base,
        prefix_len: 24,
    }
}

/// Frozen domain separator for the bytes a record signature covers.
pub const RECORD_DOMAIN: &str = "tsunagi-signed-record-v3";

/// Longest hostname a record may carry.
///
/// One DNS label's worth. It bounds what arrives from the network before
/// anything is allocated for it, and keeps a name short enough to print in a
/// column.
pub const MAX_HOSTNAME_LEN: usize = 63;

/// Largest number of records accepted in one exchange.
pub const MAX_RECORDS_PER_MESSAGE: usize = 256;

/// Why a record could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// The signature does not match the author.
    #[error("record signature does not verify")]
    BadSignature,
    /// The author field is not a valid public key.
    #[error("record author is not a valid endpoint id")]
    BadAuthor,
    /// The signature field is not the right length.
    #[error("record signature is not {expected} bytes")]
    BadSignatureLength {
        /// Expected length.
        expected: usize,
    },
    /// The record belongs to a different network.
    #[error("record belongs to another network")]
    WrongNetwork,
    /// The record's contents are not acceptable.
    #[error("record is malformed: {0}")]
    Malformed(&'static str),
}

/// What an author is saying about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RecordBody {
    /// Everything this author currently asserts about itself.
    ///
    /// One record per author, so everything it claims travels together and a
    /// later version supersedes the lot. That is what makes changing a claim
    /// a revocation of the previous one rather than an addition beside it:
    /// there is no way to leave the old value standing.
    Claim {
        /// The IPv4 overlay address this author holds, if it holds one.
        address: Option<Ipv4Addr>,
        /// The overlay range that address was allocated from.
        ///
        /// The range travels with the claim so that a participant joining
        /// later learns which range the network actually settled on, rather
        /// than having to be told.
        range: Option<Ipv4Range>,
        /// The name this author answers to.
        hostname: Option<String>,
        /// When this author first claimed that name, in milliseconds since
        /// the Unix epoch, kept across every later version that keeps the
        /// name. It is what makes a name belong to whoever claimed it first
        /// rather than to whoever happens to sort lowest, so a member that
        /// arrives later with the same name cannot take it over.
        ///
        /// The author's own word: a member with a wrong clock can claim an
        /// earlier time. That costs it nothing it could not do by other
        /// means, since anybody who knows the network secret is a member,
        /// and it cannot take an address or reach anything it was not
        /// already entitled to.
        hostname_since: Option<u64>,
    },
    /// This author gives up everything it claimed.
    ///
    /// A tombstone, not an absence: it is a positive statement, so it
    /// survives merging and cannot be undone by a replica that simply has not
    /// heard of it. Published when a device key is replaced, so the address
    /// and name it held are freed for somebody else rather than reserved
    /// forever to a key nobody has.
    Release,
}

impl RecordBody {
    /// The address this body claims, if any.
    pub fn claimed_address(&self) -> Option<Ipv4Addr> {
        match self {
            RecordBody::Claim { address, .. } => *address,
            RecordBody::Release => None,
        }
    }

    /// The range this body names, if any.
    pub fn range(&self) -> Option<Ipv4Range> {
        match self {
            RecordBody::Claim { range, .. } => *range,
            RecordBody::Release => None,
        }
    }

    /// The hostname this body claims, if any.
    pub fn hostname(&self) -> Option<&str> {
        match self {
            RecordBody::Claim { hostname, .. } => hostname.as_deref(),
            RecordBody::Release => None,
        }
    }

    /// When the author first claimed the hostname, if it has one.
    pub fn hostname_since(&self) -> Option<u64> {
        match self {
            RecordBody::Claim { hostname_since, .. } => *hostname_since,
            RecordBody::Release => None,
        }
    }

    fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        match self {
            RecordBody::Claim {
                address,
                range,
                hostname,
                hostname_since,
            } => {
                push_lp(&mut out, b"claim");
                push_opt(
                    &mut out,
                    address
                        .map(|address| address.octets())
                        .as_ref()
                        .map(|o| &o[..]),
                );
                push_opt(
                    &mut out,
                    range
                        .map(|range| {
                            let mut bytes = range.base.octets().to_vec();
                            bytes.push(range.prefix_len);
                            bytes
                        })
                        .as_deref(),
                );
                push_opt(&mut out, hostname.as_deref().map(str::as_bytes));
                push_opt(
                    &mut out,
                    hostname_since
                        .map(|since| since.to_be_bytes())
                        .as_ref()
                        .map(|bytes| &bytes[..]),
                );
            }
            RecordBody::Release => {
                push_lp(&mut out, b"release");
            }
        }
        out
    }
}

/// Reduces a hostname to something safe to store, compare and print.
///
/// Three jobs at once. It bounds the length, so a record from the network
/// cannot carry an unbounded string. It strips everything outside a
/// conservative set, so a name can never be mistaken for a path, an option or
/// a shell word by anything downstream — nothing here is ever executed, and
/// this keeps it that way even if some later caller is careless. And it
/// lower-cases, so that two members claiming the same name in different cases
/// are recognised as claiming the same name rather than quietly both holding
/// it.
pub fn sanitise_hostname(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_HOSTNAME_LEN));
    for ch in raw.chars() {
        if out.len() >= MAX_HOSTNAME_LEN {
            break;
        }
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_') {
            out.push(ch);
        }
    }
    // A name that is only separators distinguishes nothing.
    let trimmed = out.trim_matches(|ch| matches!(ch, '-' | '.' | '_'));
    trimmed.to_string()
}

/// Writes an optional value unambiguously: a presence byte, then the value.
fn push_opt(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            out.push(1);
            push_lp(out, bytes);
        }
        None => out.push(0),
    }
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// One author's current statement about itself, signed by that author.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecord {
    /// The author's persistent endpoint id.
    pub author: [u8; 32],
    /// The network the statement belongs to.
    pub network: [u8; 32],
    /// The author's own counter. Only the author increments it.
    pub version: u64,
    /// The statement.
    pub body: RecordBody,
    /// Ed25519 signature over [`SignedRecord::canonical_bytes`].
    pub signature: Vec<u8>,
}

impl SignedRecord {
    /// The bytes a signature covers.
    ///
    /// Length-prefixed throughout, so no two different records can produce the
    /// same bytes.
    pub fn canonical_bytes(
        network: NetworkId,
        author: EndpointId,
        version: u64,
        body: &RecordBody,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        push_lp(&mut out, RECORD_DOMAIN.as_bytes());
        push_lp(&mut out, network.as_bytes());
        push_lp(&mut out, author.as_bytes());
        push_lp(&mut out, &version.to_be_bytes());
        push_lp(&mut out, &body.canonical());
        out
    }

    /// Signs a new record with the author's persistent device key.
    pub fn sign(secret: &SecretKey, network: NetworkId, version: u64, body: RecordBody) -> Self {
        let author = secret.public();
        let signature = secret.sign(&Self::canonical_bytes(network, author, version, &body));
        Self {
            author: *author.as_bytes(),
            network: *network.as_bytes(),
            version,
            body,
            signature: signature.to_bytes().to_vec(),
        }
    }

    /// The author, if the field is a valid key.
    pub fn author_id(&self) -> Result<EndpointId, StateError> {
        EndpointId::from_bytes(&self.author).map_err(|_| StateError::BadAuthor)
    }

    /// The network this record belongs to.
    pub fn network_id(&self) -> NetworkId {
        NetworkId::from_bytes(self.network)
    }

    /// Checks the signature and that the record belongs to `network`.
    ///
    /// Everything that reaches this from the network goes through it first.
    pub fn verify(&self, network: NetworkId) -> Result<EndpointId, StateError> {
        if self.network != *network.as_bytes() {
            return Err(StateError::WrongNetwork);
        }
        if let RecordBody::Claim {
            address,
            range,
            hostname,
            hostname_since,
        } = &self.body
        {
            if hostname.is_none() && hostname_since.is_some() {
                return Err(StateError::Malformed("a time was claimed for no hostname"));
            }
            // Bounds before anything is believed, because all of this came
            // off the network.
            if let Some(range) = range {
                if range.prefix_len > 30 {
                    return Err(StateError::Malformed("claimed range has no room for hosts"));
                }
                if let Some(address) = address
                    && !range.contains(*address)
                {
                    return Err(StateError::Malformed(
                        "claimed address is outside its range",
                    ));
                }
            } else if address.is_some() {
                return Err(StateError::Malformed("claimed an address with no range"));
            }
            if let Some(hostname) = hostname {
                // Rejected rather than sanitised: a name that does not
                // survive sanitising unchanged would hash and compare
                // differently from what the author signed, so accepting a
                // repaired version would mean believing something nobody
                // signed.
                if hostname.len() > MAX_HOSTNAME_LEN {
                    return Err(StateError::Malformed("claimed hostname is too long"));
                }
                if *hostname != sanitise_hostname(hostname) {
                    return Err(StateError::Malformed("claimed hostname is not canonical"));
                }
            }
        }

        let author = self.author_id()?;
        let raw: [u8; Signature::LENGTH] =
            self.signature
                .as_slice()
                .try_into()
                .map_err(|_| StateError::BadSignatureLength {
                    expected: Signature::LENGTH,
                })?;
        let signature = Signature::from_bytes(&raw);
        author
            .verify(
                &Self::canonical_bytes(network, author, self.version, &self.body),
                &signature,
            )
            .map_err(|_| StateError::BadSignature)?;
        Ok(author)
    }
}

/// What merging one record did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Merged {
    /// Nothing was known about this author; the record was taken.
    Added,
    /// It replaced an older version from the same author.
    Updated,
    /// Already known, or older than what is held. Nothing changed.
    ///
    /// An older version never rolls back a newer one.
    Ignored,
    /// Two different records from one author at the same version.
    ///
    /// Resolved deterministically so every replica picks the same one, and
    /// reported because it means a key is being used from two places at once.
    Conflicted,
}

/// Everything known about one network, one record per author.
#[derive(Debug, Clone, Default)]
pub struct StateSet {
    records: HashMap<EndpointId, SignedRecord>,
}

impl StateSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a set from records already known to be verified.
    pub fn from_verified(records: impl IntoIterator<Item = (EndpointId, SignedRecord)>) -> Self {
        Self {
            records: records.into_iter().collect(),
        }
    }

    /// How many authors are known.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether nothing is known.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The record of one author.
    pub fn get(&self, author: &EndpointId) -> Option<&SignedRecord> {
        self.records.get(author)
    }

    /// Every record, in a stable order.
    pub fn records(&self) -> Vec<SignedRecord> {
        let mut authors: Vec<&EndpointId> = self.records.keys().collect();
        authors.sort_by_key(|author| *author.as_bytes());
        authors
            .into_iter()
            .filter_map(|author| self.records.get(author).cloned())
            .collect()
    }

    /// Merges one record, verifying it first.
    ///
    /// Merging is into the existing set, never a wholesale replacement, and an
    /// author missing from an incoming batch is left untouched — absence is
    /// not deletion.
    pub fn merge(
        &mut self,
        network: NetworkId,
        record: SignedRecord,
    ) -> Result<Merged, StateError> {
        let author = record.verify(network)?;

        match self.records.get(&author) {
            None => {
                self.records.insert(author, record);
                Ok(Merged::Added)
            }
            Some(existing) if existing.version < record.version => {
                self.records.insert(author, record);
                Ok(Merged::Updated)
            }
            Some(existing) if existing.version > record.version => Ok(Merged::Ignored),
            Some(existing) if existing.body == record.body => Ok(Merged::Ignored),
            Some(existing) => {
                // Same author, same version, different content: the author's
                // key is in use in two places. Neither is more true than the
                // other, so pick by a rule every replica computes identically
                // and report it rather than letting replicas diverge.
                if record.signature < existing.signature {
                    self.records.insert(author, record);
                }
                Ok(Merged::Conflicted)
            }
        }
    }

    /// Merges a batch, returning what happened and the first error seen.
    ///
    /// A bad record in a batch is skipped; the rest still merge.
    pub fn merge_all(
        &mut self,
        network: NetworkId,
        records: impl IntoIterator<Item = SignedRecord>,
    ) -> (Vec<Merged>, Vec<StateError>) {
        let mut outcomes = Vec::new();
        let mut errors = Vec::new();
        for record in records {
            match self.merge(network, record) {
                Ok(outcome) => outcomes.push(outcome),
                Err(err) => errors.push(err),
            }
        }
        (outcomes, errors)
    }

    /// Who currently holds each claimed address.
    ///
    /// When two authors claim one address, the one whose endpoint id sorts
    /// lower holds it — again a rule every replica computes identically. The
    /// other is expected to notice and claim a different one.
    pub fn address_holders(&self) -> HashMap<Ipv4Addr, EndpointId> {
        let mut holders: HashMap<Ipv4Addr, EndpointId> = HashMap::new();
        for (author, record) in &self.records {
            let Some(address) = record.body.claimed_address() else {
                continue;
            };
            holders
                .entry(address)
                .and_modify(|held| {
                    if author.as_bytes() < held.as_bytes() {
                        *held = *author;
                    }
                })
                .or_insert(*author);
        }
        holders
    }

    /// Who currently holds each claimed hostname.
    ///
    /// A name belongs to the member that claimed it first, and the others
    /// that claim it keep working by address but are not found by that name.
    /// "First" is the time each author signed into its own claim, with the
    /// lower id deciding a tie and a claim with no time counting as last, so
    /// every replica reaches the same answer about who has it without
    /// asking anybody. It is a pure function of the records: nothing depends
    /// on the order they arrived in, so there is no race to lose.
    pub fn hostname_holders(&self) -> HashMap<String, EndpointId> {
        let mut holders: HashMap<String, (u64, EndpointId)> = HashMap::new();
        for (author, record) in &self.records {
            let Some(hostname) = record.body.hostname() else {
                continue;
            };
            let claim = (record.body.hostname_since().unwrap_or(u64::MAX), *author);
            holders
                .entry(hostname.to_string())
                .and_modify(|held| {
                    if (claim.0, claim.1.as_bytes()) < (held.0, held.1.as_bytes()) {
                        *held = claim;
                    }
                })
                .or_insert(claim);
        }
        holders
            .into_iter()
            .map(|(hostname, (_, author))| (hostname, author))
            .collect()
    }

    /// The hostname an author holds, if it holds one uncontested.
    pub fn hostname_of(&self, author: &EndpointId) -> Option<&str> {
        let hostname = self.records.get(author)?.body.hostname()?;
        (self.hostname_holders().get(hostname) == Some(author)).then_some(hostname)
    }

    /// The name an author claimed and the member that holds it instead, when
    /// somebody who claimed it earlier does.
    pub fn hostname_taken(&self, author: &EndpointId) -> Option<(&str, EndpointId)> {
        let hostname = self.records.get(author)?.body.hostname()?;
        let holder = *self.hostname_holders().get(hostname)?;
        (holder != *author).then_some((hostname, holder))
    }

    /// When an author first claimed the name it holds now, if it has one.
    pub fn hostname_since_of(&self, author: &EndpointId) -> Option<u64> {
        self.records.get(author)?.body.hostname_since()
    }

    /// The address an author holds, if it holds one uncontested.
    pub fn address_of(&self, author: &EndpointId) -> Option<Ipv4Addr> {
        let address = self.records.get(author)?.body.claimed_address()?;
        (self.address_holders().get(&address) == Some(author)).then_some(address)
    }

    /// The range the network settled on, if anybody has said.
    ///
    /// When claims disagree, the one from the lowest author id wins, so every
    /// replica reaches the same answer. A participant joining later therefore
    /// adopts the range already in use instead of imposing its own.
    pub fn agreed_range(&self) -> Option<Ipv4Range> {
        let mut authors: Vec<&EndpointId> = self.records.keys().collect();
        authors.sort_by_key(|author| *author.as_bytes());
        authors
            .into_iter()
            .find_map(|author| self.records.get(author)?.body.range())
    }

    /// The highest version this author has published, as far as is known.
    pub fn version_of(&self, author: &EndpointId) -> u64 {
        self.records.get(author).map_or(0, |record| record.version)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};

    fn network(name: &str) -> NetworkId {
        NetworkKeys::derive(
            &NetworkName::new(name).unwrap(),
            &NetworkSecret::from_bytes(vec![6u8; 32]).unwrap(),
        )
        .network_id()
    }

    fn range() -> Ipv4Range {
        "10.13.37.0/24".parse().unwrap()
    }

    fn claim(address: &str) -> RecordBody {
        RecordBody::Claim {
            address: Some(address.parse().unwrap()),
            range: Some(range()),
            hostname: None,
            hostname_since: None,
        }
    }

    #[test]
    fn a_record_verifies_only_against_its_own_author_and_network() {
        let id = network("verify");
        let secret = SecretKey::generate();
        let record = SignedRecord::sign(&secret, id, 1, claim("10.13.37.5"));

        assert_eq!(record.verify(id).unwrap(), secret.public());
        // A record from another network does not apply here.
        assert_eq!(
            record.verify(network("other")).unwrap_err(),
            StateError::WrongNetwork
        );

        // Changing anything invalidates the signature.
        for tampered in [
            SignedRecord {
                version: 2,
                ..record.clone()
            },
            SignedRecord {
                body: claim("10.13.37.6"),
                ..record.clone()
            },
            SignedRecord {
                author: *SecretKey::generate().public().as_bytes(),
                ..record.clone()
            },
        ] {
            assert!(tampered.verify(id).is_err(), "tampering must be caught");
        }
    }

    #[test]
    fn malformed_records_are_rejected_without_panicking() {
        let id = network("malformed");
        let secret = SecretKey::generate();
        let good = SignedRecord::sign(&secret, id, 1, claim("10.13.37.5"));

        let short_signature = SignedRecord {
            signature: vec![0u8; 8],
            ..good.clone()
        };
        assert!(matches!(
            short_signature.verify(id),
            Err(StateError::BadSignatureLength { .. })
        ));

        // An address outside the range it names is nonsense.
        let outside = SignedRecord::sign(
            &secret,
            id,
            1,
            RecordBody::Claim {
                address: Some("10.99.0.1".parse().unwrap()),
                range: Some(range()),
                hostname: None,
                hostname_since: None,
            },
        );
        assert!(matches!(outside.verify(id), Err(StateError::Malformed(_))));

        let no_hosts = SignedRecord::sign(
            &secret,
            id,
            1,
            RecordBody::Claim {
                address: Some("10.13.37.1".parse().unwrap()),
                range: Some(Ipv4Range {
                    base: "10.13.37.0".parse().unwrap(),
                    prefix_len: 31,
                }),
                hostname: None,
                hostname_since: None,
            },
        );
        assert!(matches!(no_hosts.verify(id), Err(StateError::Malformed(_))));
    }

    #[test]
    fn a_hostname_is_reduced_to_something_safe_to_store_and_compare() {
        // Lower-cased, so two members cannot both "own" the same name in
        // different cases without noticing.
        assert_eq!(sanitise_hostname("Music"), "music");
        // Stripped, so nothing downstream can mistake a name for a path, an
        // option or a shell word.
        assert_eq!(sanitise_hostname("ab; rm -rf /"), "abrm-rf");
        assert_eq!(sanitise_hostname("a/b\\c"), "abc");
        assert_eq!(sanitise_hostname("host name"), "hostname");
        // Bounded before anything is allocated for it.
        assert_eq!(sanitise_hostname(&"x".repeat(200)).len(), MAX_HOSTNAME_LEN);
        // A name of nothing but separators distinguishes nothing.
        assert_eq!(sanitise_hostname("---"), "");
        assert_eq!(sanitise_hostname(""), "");
        // Already canonical names survive untouched, or the check in
        // `verify` would reject what this produced.
        for name in ["music", "ab-laptop", "host.example", "a_b.c-1"] {
            assert_eq!(sanitise_hostname(name), name);
        }
    }

    #[test]
    fn a_hostname_that_is_not_canonical_is_rejected_rather_than_repaired() {
        // Repairing it would mean storing something the author never signed.
        let secret = SecretKey::generate();
        let id = network("naming");
        for bad in ["Music", "ab; rm", "x".repeat(MAX_HOSTNAME_LEN + 1).as_str()] {
            let record = SignedRecord::sign(
                &secret,
                id,
                1,
                RecordBody::Claim {
                    address: None,
                    range: None,
                    hostname: Some(bad.to_string()),
                    hostname_since: None,
                },
            );
            assert!(
                matches!(record.verify(id), Err(StateError::Malformed(_))),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn an_address_without_a_range_is_rejected() {
        let secret = SecretKey::generate();
        let id = network("naming");
        let record = SignedRecord::sign(
            &secret,
            id,
            1,
            RecordBody::Claim {
                address: Some("10.13.37.5".parse().unwrap()),
                range: None,
                hostname: None,
                hostname_since: None,
            },
        );
        assert!(matches!(record.verify(id), Err(StateError::Malformed(_))));
    }

    #[test]
    fn two_members_claiming_one_name_resolve_it_the_same_way_everywhere() {
        // The same rule as addresses: a name is owned, and every replica has
        // to reach the same answer about who owns it with nobody to ask.
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        let id = network("naming");
        let named = |secret: &SecretKey| {
            SignedRecord::sign(
                secret,
                id,
                1,
                RecordBody::Claim {
                    address: None,
                    range: None,
                    hostname: Some("music".into()),
                    hostname_since: None,
                },
            )
        };

        let mut set = StateSet::new();
        set.merge(id, named(&a)).unwrap();
        set.merge(id, named(&b)).unwrap();

        let (lower, higher) = if a.public().as_bytes() < b.public().as_bytes() {
            (a.public(), b.public())
        } else {
            (b.public(), a.public())
        };
        assert_eq!(set.hostname_of(&lower), Some("music"));
        assert_eq!(
            set.hostname_of(&higher),
            None,
            "the loser does not hold the name it claimed"
        );

        // And the order the records arrived in cannot change the answer.
        let mut reversed = StateSet::new();
        reversed.merge(id, named(&b)).unwrap();
        reversed.merge(id, named(&a)).unwrap();
        assert_eq!(reversed.hostname_of(&lower), Some("music"));
    }

    #[test]
    fn changing_a_name_revokes_the_old_one_everywhere() {
        // There is one record per author, so a new version replaces the whole
        // claim. The previous name cannot survive beside it.
        let secret = SecretKey::generate();
        let id = network("naming");
        let claim = |version, name: &str| {
            SignedRecord::sign(
                &secret,
                id,
                version,
                RecordBody::Claim {
                    address: None,
                    range: None,
                    hostname: Some(name.to_string()),
                    hostname_since: None,
                },
            )
        };

        let mut set = StateSet::new();
        set.merge(id, claim(1, "old")).unwrap();
        set.merge(id, claim(2, "new")).unwrap();

        assert_eq!(set.hostname_of(&secret.public()), Some("new"));
        assert!(
            !set.hostname_holders().contains_key("old"),
            "the old name is gone, not merely shadowed"
        );

        // A replica that has not heard of the change cannot bring it back.
        set.merge(id, claim(1, "old")).unwrap();
        assert_eq!(set.hostname_of(&secret.public()), Some("new"));
    }

    fn named_at(
        secret: &SecretKey,
        id: NetworkId,
        version: u64,
        name: &str,
        since: u64,
    ) -> SignedRecord {
        SignedRecord::sign(
            secret,
            id,
            version,
            RecordBody::Claim {
                address: None,
                range: None,
                hostname: Some(name.into()),
                hostname_since: Some(since),
            },
        )
    }

    #[test]
    fn a_name_belongs_to_whoever_claimed_it_first_whatever_their_ids_or_arrival_order() {
        let id = network("naming");
        let mut keys = [SecretKey::generate(), SecretKey::generate()];
        keys.sort_by_key(|key| *key.public().as_bytes());
        let [low, high] = keys;

        // The member with the higher id claimed first, so it holds the name,
        // and the lower id does not take it back by sorting first.
        let early = named_at(&high, id, 1, "music", 1_000);
        let late = named_at(&low, id, 1, "music", 2_000);
        for order in [[&early, &late], [&late, &early]] {
            let mut set = StateSet::new();
            for record in order {
                set.merge(id, (*record).clone()).unwrap();
            }
            assert_eq!(set.hostname_of(&high.public()), Some("music"));
            assert_eq!(set.hostname_of(&low.public()), None);
            assert_eq!(
                set.hostname_taken(&low.public()),
                Some(("music", high.public()))
            );
            assert_eq!(set.hostname_taken(&high.public()), None);
        }

        // At the same instant the lower id decides, the same way everywhere.
        let mut set = StateSet::new();
        set.merge(id, named_at(&high, id, 1, "music", 5)).unwrap();
        set.merge(id, named_at(&low, id, 1, "music", 5)).unwrap();
        assert_eq!(set.hostname_of(&low.public()), Some("music"));
        assert_eq!(set.hostname_of(&high.public()), None);
    }

    #[test]
    fn a_name_that_loses_is_found_again_once_the_holder_lets_it_go() {
        let id = network("naming");
        let first = SecretKey::generate();
        let second = SecretKey::generate();
        let mut set = StateSet::new();
        set.merge(id, named_at(&first, id, 1, "music", 1)).unwrap();
        set.merge(id, named_at(&second, id, 1, "music", 2)).unwrap();
        assert_eq!(set.hostname_of(&second.public()), None);

        // Renaming starts the clock afresh, so it cannot be used to jump the
        // queue for a name somebody else already holds.
        set.merge(id, named_at(&first, id, 2, "other", 3)).unwrap();
        assert_eq!(set.hostname_of(&second.public()), Some("music"));
        set.merge(id, named_at(&first, id, 3, "music", 4)).unwrap();
        assert_eq!(set.hostname_of(&second.public()), Some("music"));
        assert_eq!(set.hostname_of(&first.public()), None);

        // And a release hands it on.
        set.merge(id, SignedRecord::sign(&second, id, 2, RecordBody::Release))
            .unwrap();
        assert_eq!(set.hostname_of(&first.public()), Some("music"));
    }

    #[test]
    fn a_time_with_no_name_is_not_a_valid_claim() {
        let id = network("naming");
        let secret = SecretKey::generate();
        let record = SignedRecord::sign(
            &secret,
            id,
            1,
            RecordBody::Claim {
                address: None,
                range: None,
                hostname: None,
                hostname_since: Some(1),
            },
        );
        assert!(matches!(record.verify(id), Err(StateError::Malformed(_))));

        // The time is signed: moving it breaks the signature, so nobody can
        // improve another member's place in the queue.
        let mut forged = named_at(&secret, id, 1, "music", 9_000);
        if let RecordBody::Claim { hostname_since, .. } = &mut forged.body {
            *hostname_since = Some(1);
        }
        assert_eq!(forged.verify(id).unwrap_err(), StateError::BadSignature);
    }

    #[test]
    fn a_release_gives_up_the_name_as_well_as_the_address() {
        let secret = SecretKey::generate();
        let id = network("naming");
        let mut set = StateSet::new();
        set.merge(
            id,
            SignedRecord::sign(
                &secret,
                id,
                1,
                RecordBody::Claim {
                    address: Some("10.13.37.5".parse().unwrap()),
                    range: Some(range()),
                    hostname: Some("music".into()),
                    hostname_since: None,
                },
            ),
        )
        .unwrap();
        set.merge(id, SignedRecord::sign(&secret, id, 2, RecordBody::Release))
            .unwrap();

        assert_eq!(set.address_of(&secret.public()), None);
        assert_eq!(set.hostname_of(&secret.public()), None);
        assert!(set.address_holders().is_empty());
        assert!(set.hostname_holders().is_empty());
    }

    #[test]
    fn a_newer_version_wins_and_an_older_one_never_rolls_back() {
        let id = network("versions");
        let secret = SecretKey::generate();
        let mut set = StateSet::new();

        let first = SignedRecord::sign(&secret, id, 1, claim("10.13.37.5"));
        let second = SignedRecord::sign(&secret, id, 2, claim("10.13.37.6"));

        assert_eq!(set.merge(id, first.clone()).unwrap(), Merged::Added);
        assert_eq!(set.merge(id, second.clone()).unwrap(), Merged::Updated);
        // The old one coming back later must not undo the new one.
        assert_eq!(set.merge(id, first).unwrap(), Merged::Ignored);
        assert_eq!(
            set.address_of(&secret.public()),
            Some("10.13.37.6".parse().unwrap())
        );
        // Merging the same record twice changes nothing.
        assert_eq!(set.merge(id, second).unwrap(), Merged::Ignored);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn two_authors_claiming_one_address_resolve_the_same_way_everywhere() {
        let id = network("clash");
        let (low, high) = {
            let a = SecretKey::generate();
            let b = SecretKey::generate();
            if a.public().as_bytes() < b.public().as_bytes() {
                (a, b)
            } else {
                (b, a)
            }
        };

        let record_low = SignedRecord::sign(&low, id, 1, claim("10.13.37.5"));
        let record_high = SignedRecord::sign(&high, id, 1, claim("10.13.37.5"));

        // Merge order must not change the outcome.
        let mut forwards = StateSet::new();
        forwards.merge(id, record_low.clone()).unwrap();
        forwards.merge(id, record_high.clone()).unwrap();

        let mut backwards = StateSet::new();
        backwards.merge(id, record_high).unwrap();
        backwards.merge(id, record_low).unwrap();

        let expected = Some(low.public());
        assert_eq!(
            forwards
                .address_holders()
                .get(&"10.13.37.5".parse().unwrap()),
            expected.as_ref()
        );
        assert_eq!(
            backwards
                .address_holders()
                .get(&"10.13.37.5".parse().unwrap()),
            expected.as_ref()
        );
        // The loser holds nothing, and is expected to pick again.
        assert_eq!(forwards.address_of(&high.public()), None);
        assert_eq!(
            forwards.address_of(&low.public()),
            Some("10.13.37.5".parse().unwrap())
        );
    }

    #[test]
    fn one_key_used_in_two_places_is_reported_not_silently_merged() {
        let id = network("split-brain");
        let secret = SecretKey::generate();
        let mut set = StateSet::new();

        let here = SignedRecord::sign(&secret, id, 3, claim("10.13.37.5"));
        let there = SignedRecord::sign(&secret, id, 3, claim("10.13.37.9"));

        set.merge(id, here.clone()).unwrap();
        assert_eq!(set.merge(id, there.clone()).unwrap(), Merged::Conflicted);

        // Whatever it picked, it must pick the same thing from the other side.
        let mut other = StateSet::new();
        other.merge(id, there).unwrap();
        assert_eq!(other.merge(id, here).unwrap(), Merged::Conflicted);
        assert_eq!(
            set.get(&secret.public()).unwrap(),
            other.get(&secret.public()).unwrap()
        );
    }

    #[test]
    fn a_release_is_a_statement_that_survives_merging() {
        let id = network("release");
        let secret = SecretKey::generate();
        let mut set = StateSet::new();

        set.merge(id, SignedRecord::sign(&secret, id, 1, claim("10.13.37.5")))
            .unwrap();
        assert!(set.address_of(&secret.public()).is_some());

        set.merge(id, SignedRecord::sign(&secret, id, 2, RecordBody::Release))
            .unwrap();
        assert_eq!(set.address_of(&secret.public()), None);
        assert!(set.address_holders().is_empty());

        // The old claim arriving late does not resurrect the address.
        assert_eq!(
            set.merge(id, SignedRecord::sign(&secret, id, 1, claim("10.13.37.5")))
                .unwrap(),
            Merged::Ignored
        );
        assert_eq!(set.address_of(&secret.public()), None);
    }

    #[test]
    fn a_batch_with_one_bad_record_still_merges_the_rest() {
        let id = network("batch");
        let good = SecretKey::generate();
        let mut set = StateSet::new();

        let valid = SignedRecord::sign(&good, id, 1, claim("10.13.37.5"));
        let forged = SignedRecord {
            signature: vec![0u8; Signature::LENGTH],
            ..SignedRecord::sign(&SecretKey::generate(), id, 1, claim("10.13.37.6"))
        };

        let (outcomes, errors) = set.merge_all(id, [forged, valid]);
        assert_eq!(outcomes, vec![Merged::Added]);
        assert_eq!(errors, vec![StateError::BadSignature]);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn a_later_joiner_adopts_the_range_already_in_use() {
        let id = network("ranges");
        let mut set = StateSet::new();
        assert_eq!(set.agreed_range(), None, "nothing known yet");

        let custom: Ipv4Range = "10.99.0.0/16".parse().unwrap();
        let author = SecretKey::generate();
        set.merge(
            id,
            SignedRecord::sign(
                &author,
                id,
                1,
                RecordBody::Claim {
                    address: Some("10.99.0.7".parse().unwrap()),
                    range: Some(custom),
                    hostname: None,
                    hostname_since: None,
                },
            ),
        )
        .unwrap();
        assert_eq!(set.agreed_range(), Some(custom));
    }

    #[test]
    fn the_signed_bytes_are_unambiguous() {
        let id = network("encoding");
        let author = SecretKey::generate().public();
        // Two bodies whose parts would concatenate identically must not
        // produce the same signed bytes.
        let a = SignedRecord::canonical_bytes(id, author, 1, &claim("10.13.37.5"));
        let b = SignedRecord::canonical_bytes(id, author, 1, &claim("10.13.37.6"));
        assert_ne!(a, b);
        assert_ne!(
            a,
            SignedRecord::canonical_bytes(id, author, 2, &claim("10.13.37.5"))
        );
        assert_ne!(
            a,
            SignedRecord::canonical_bytes(network("other"), author, 1, &claim("10.13.37.5"))
        );
    }

    #[test]
    fn a_derived_range_is_the_same_wherever_it_is_derived() {
        // Every member has to arrive at it without being told, so it comes
        // from the one thing they all already agree on.
        let network = NetworkKeys::derive(
            &NetworkName::new("second").unwrap(),
            &NetworkSecret::from_bytes([7u8; 32]).unwrap(),
        )
        .network_id();
        let once = derived_ipv4_range(network);
        assert_eq!(once, derived_ipv4_range(network));
        assert_eq!(once.prefix_len, 24);
        assert_eq!(once.base.octets()[0], 10, "inside 10/8 like the default");
        assert_ne!(
            once, DEFAULT_IPV4_RANGE,
            "the default belongs to whichever network asked first"
        );

        // A different network derives a different range, which is the
        // whole point of deriving it.
        let other = NetworkKeys::derive(
            &NetworkName::new("third").unwrap(),
            &NetworkSecret::from_bytes([9u8; 32]).unwrap(),
        )
        .network_id();
        assert_ne!(once, derived_ipv4_range(other));
    }
}
