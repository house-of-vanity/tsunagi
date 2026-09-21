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

/// Frozen domain separator for the bytes a record signature covers.
pub const RECORD_DOMAIN: &str = "tsunagi-signed-record-v1";

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
    /// This author holds an IPv4 overlay address, in this range.
    ///
    /// The range travels with the claim so that a participant joining later
    /// learns which range the network actually settled on, rather than having
    /// to be told.
    Ipv4Claim {
        /// The address this author holds.
        address: Ipv4Addr,
        /// The overlay range it was allocated from.
        range: Ipv4Range,
    },
    /// This author gave its address up.
    ///
    /// A tombstone, not an absence: it is a positive statement, so it
    /// survives merging and cannot be undone by a replica that simply has not
    /// heard of it.
    Ipv4Release,
}

impl RecordBody {
    /// The address this body claims, if any.
    pub fn claimed_address(&self) -> Option<Ipv4Addr> {
        match self {
            RecordBody::Ipv4Claim { address, .. } => Some(*address),
            RecordBody::Ipv4Release => None,
        }
    }

    /// The range this body names, if any.
    pub fn range(&self) -> Option<Ipv4Range> {
        match self {
            RecordBody::Ipv4Claim { range, .. } => Some(*range),
            RecordBody::Ipv4Release => None,
        }
    }

    fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        match self {
            RecordBody::Ipv4Claim { address, range } => {
                push_lp(&mut out, b"ipv4-claim");
                push_lp(&mut out, &address.octets());
                push_lp(&mut out, &range.base.octets());
                push_lp(&mut out, &[range.prefix_len]);
            }
            RecordBody::Ipv4Release => {
                push_lp(&mut out, b"ipv4-release");
            }
        }
        out
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
        if let RecordBody::Ipv4Claim { address, range } = &self.body {
            if range.prefix_len > 30 {
                return Err(StateError::Malformed("claimed range has no room for hosts"));
            }
            if !range.contains(*address) {
                return Err(StateError::Malformed(
                    "claimed address is outside its range",
                ));
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
        RecordBody::Ipv4Claim {
            address: address.parse().unwrap(),
            range: range(),
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
            RecordBody::Ipv4Claim {
                address: "10.99.0.1".parse().unwrap(),
                range: range(),
            },
        );
        assert!(matches!(outside.verify(id), Err(StateError::Malformed(_))));

        let no_hosts = SignedRecord::sign(
            &secret,
            id,
            1,
            RecordBody::Ipv4Claim {
                address: "10.13.37.1".parse().unwrap(),
                range: Ipv4Range {
                    base: "10.13.37.0".parse().unwrap(),
                    prefix_len: 31,
                },
            },
        );
        assert!(matches!(no_hosts.verify(id), Err(StateError::Malformed(_))));
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

        set.merge(
            id,
            SignedRecord::sign(&secret, id, 2, RecordBody::Ipv4Release),
        )
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
                RecordBody::Ipv4Claim {
                    address: "10.99.0.7".parse().unwrap(),
                    range: custom,
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
}
