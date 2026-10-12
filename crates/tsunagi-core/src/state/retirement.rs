//! A member may retire an observed claim, never another identity's future.
use iroh::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};

use super::{RecordBody, SignedRecord, StateError, push_lp};
use crate::NetworkId;

/// Maximum encoded retirement size, including its bounded claim proof.
pub const MAX_RETIREMENT_LEN: usize = 1024;

/// A network member's signed retirement of a proved claim version.
///
/// The original author's signed claim proves the cutoff really existed.
/// Newer claims remain valid. This is neither a forged Release nor a ban.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRetirement {
    /// Device identity of the member requesting cleanup.
    pub author: [u8; 32],
    /// Network in which cleanup applies.
    pub network: [u8; 32],
    /// Requester's durable author counter, committed with this marker.
    pub version: u64,
    /// The target's original signed claim; bounds the retired version.
    pub target: SignedRecord,
    /// Requester's Ed25519 signature over this marker and its proof.
    pub signature: Vec<u8>,
}

impl SignedRetirement {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(768);
        push_lp(&mut out, b"tsunagi-node-retirement/v1");
        push_lp(&mut out, &self.network);
        push_lp(&mut out, &self.author);
        push_lp(&mut out, &self.version.to_be_bytes());
        // Bind every field of the original signed claim, including its signature.
        push_lp(&mut out, &self.target.network);
        push_lp(&mut out, &self.target.author);
        push_lp(&mut out, &self.target.version.to_be_bytes());
        push_lp(&mut out, &self.target.body.canonical());
        push_lp(&mut out, &self.target.signature);
        out
    }

    /// Signs a marker with the requesting member's persistent device key.
    pub fn sign(
        secret: &SecretKey,
        network: NetworkId,
        version: u64,
        target: SignedRecord,
    ) -> Self {
        let mut marker = Self {
            author: *secret.public().as_bytes(),
            network: *network.as_bytes(),
            version,
            target,
            signature: Vec::new(),
        };
        marker.signature = secret.sign(&marker.canonical_bytes()).to_bytes().to_vec();
        marker
    }

    /// Verifies both authors, scope and a finite, genuinely signed cutoff.
    pub fn verify(&self, network: NetworkId) -> Result<EndpointId, StateError> {
        if self.network != *network.as_bytes() {
            return Err(StateError::WrongNetwork);
        }
        if self.version == 0 || self.version > i64::MAX as u64 {
            return Err(StateError::Malformed("retirement version is out of range"));
        }
        if !matches!(self.target.body, RecordBody::Claim { .. }) {
            return Err(StateError::Malformed("only a claim can be retired"));
        }
        let target = self.target.verify(network)?;
        let author = EndpointId::from_bytes(&self.author).map_err(|_| StateError::BadAuthor)?;
        if author == target {
            return Err(StateError::Malformed(
                "use Release to retire your own claim",
            ));
        }
        let raw: [u8; Signature::LENGTH] =
            self.signature
                .as_slice()
                .try_into()
                .map_err(|_| StateError::BadSignatureLength {
                    expected: Signature::LENGTH,
                })?;
        author
            .verify(&self.canonical_bytes(), &Signature::from_bytes(&raw))
            .map_err(|_| StateError::BadSignature)?;
        Ok(target)
    }

    /// A deterministic strongest marker per target, independent of arrival order.
    pub(crate) fn supersedes(&self, other: &Self) -> bool {
        self.target.version > other.target.version
            || (self.target.version == other.target.version
                && (self.canonical_bytes(), &self.signature)
                    < (other.canonical_bytes(), &other.signature))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::state::{Ipv4Range, StateSet};

    fn claim(key: &SecretKey, id: NetworkId, version: u64) -> SignedRecord {
        SignedRecord::sign(
            key,
            id,
            version,
            RecordBody::Claim {
                address: Some("10.23.0.2".parse().unwrap()),
                range: Some("10.23.0.0/24".parse::<Ipv4Range>().unwrap()),
                hostname: Some("retired".into()),
                hostname_since: Some(123),
            },
        )
    }

    #[test]
    fn markers_release_claims_in_any_merge_order_and_older_snapshots_cannot_restore_them() {
        let id = NetworkId::from_bytes([7; 32]);
        let target = SecretKey::generate();
        let cleaner = SecretKey::generate();
        let record = claim(&target, id, 5);
        let marker = SignedRetirement::sign(&cleaner, id, 8, record.clone());
        for first in [true, false] {
            let mut state = StateSet::new();
            if first {
                state.merge_retirement(id, marker.clone(), 16).unwrap();
            }
            state.merge(id, record.clone()).unwrap();
            if !first {
                state.merge_retirement(id, marker.clone(), 16).unwrap();
            }
            assert!(state.address_holders().is_empty());
            assert!(state.hostname_holders().is_empty());
            state.merge(id, claim(&target, id, 4)).unwrap();
            assert!(state.is_retired(&target.public()));
            assert!(
                state.agreed_range().is_some(),
                "cleanup does not renumber the network"
            );
            state.merge(id, claim(&target, id, 6)).unwrap();
            assert!(!state.is_retired(&target.public()));
            assert_eq!(state.hostname_of(&target.public()), Some("retired"));
        }
    }

    #[test]
    fn proof_signature_scope_tampering_future_cutoffs_and_capacity_are_checked() {
        let id = NetworkId::from_bytes([7; 32]);
        let target = SecretKey::generate();
        let cleaner = SecretKey::generate();
        let marker = SignedRetirement::sign(&cleaner, id, 8, claim(&target, id, 5));
        assert!(marker.verify(NetworkId::from_bytes([8; 32])).is_err());
        let mut forged = marker.clone();
        forged.target.version = 99;
        assert!(forged.verify(id).is_err());
        let mut forged = marker.clone();
        forged.signature[0] ^= 1;
        assert!(forged.verify(id).is_err());
        let mut proof = marker.target.clone();
        proof.version = 99;
        assert!(
            SignedRetirement::sign(&cleaner, id, 8, proof)
                .verify(id)
                .is_err()
        );
        let mut state = StateSet::new();
        assert!(state.merge_retirement(id, marker.clone(), 0).is_err());
        assert!(state.merge_retirement(id, marker.clone(), 1).unwrap());
        assert!(!state.merge_retirement(id, marker.clone(), 1).unwrap());
        assert!(postcard::to_stdvec(&marker).unwrap().len() <= MAX_RETIREMENT_LEN);
        let another = SecretKey::generate();
        assert!(
            state
                .merge_retirement(
                    id,
                    SignedRetirement::sign(&cleaner, id, 9, claim(&another, id, 1)),
                    1
                )
                .is_err()
        );
    }

    #[test]
    fn competing_cleanup_markers_converge_and_keep_the_highest_observed_cutoff() {
        let id = NetworkId::from_bytes([7; 32]);
        let target = SecretKey::generate();
        let a = SecretKey::generate();
        let b = SecretKey::generate();
        let markers = [
            SignedRetirement::sign(&a, id, 1, claim(&target, id, 4)),
            SignedRetirement::sign(&a, id, 2, claim(&target, id, 5)),
            SignedRetirement::sign(&b, id, 3, claim(&target, id, 5)),
        ];
        let mut forward = StateSet::new();
        let mut reverse = StateSet::new();
        for marker in &markers {
            forward.merge_retirement(id, marker.clone(), 16).unwrap();
        }
        for marker in markers.iter().rev() {
            reverse.merge_retirement(id, marker.clone(), 16).unwrap();
        }
        assert_eq!(forward.retirements(), reverse.retirements());
        assert_eq!(
            forward
                .retirement_of(&target.public())
                .unwrap()
                .target
                .version,
            5
        );
    }
}
