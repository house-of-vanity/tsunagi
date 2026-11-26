//! Single-use credentials scoped to an authenticated pair.
use iroh::EndpointId;
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use tsunagi::NetworkId;
use zeroize::ZeroizeOnDrop;

pub(crate) type Pair = (NetworkId, EndpointId);
pub(crate) const LIFETIME: Duration = Duration::from_secs(12);

/// An independently random public lookup value and private credential.
#[derive(ZeroizeOnDrop)]
pub struct Profile {
    /// Random request salt or XHTTP path component.
    pub tag: [u8; 32],
    /// Secret material, sent only on the already authenticated control session.
    pub secret: [u8; 32],
    /// Independent random selector for a wire profile with two supported methods.
    pub variant: bool,
}
impl Profile {
    pub(crate) fn fresh() -> Self {
        Self {
            tag: rand::random(),
            secret: rand::random(),
            variant: rand::random(),
        }
    }
}

/// The pair is supplied by authenticated control, never by the TCP client.
#[derive(Clone)]
pub struct Ticket {
    pub(crate) pair: Pair,
    /// Parameters of this connection attempt.
    pub profile: Arc<Profile>,
}

#[derive(Default)]
pub(crate) struct Slot {
    pub(crate) addresses: Vec<SocketAddr>,
    incoming: Option<(Arc<Profile>, Instant)>,
    // A repeated private offer cannot reauthorize a previously accepted salt.
    recent: std::collections::VecDeque<([u8; 16], Instant)>,
    pub(crate) waiting: Option<([u8; 32], oneshot::Sender<()>)>,
}

/// Bounded by enabled, authenticated memberships. At most one offer per pair.
#[derive(Default)]
pub struct Profiles(pub(crate) Mutex<HashMap<Pair, Slot>>);

impl Profiles {
    pub(crate) fn offer(&self, pair: Pair, profile: Profile) -> io::Result<()> {
        let mut slots = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if slots.iter().any(|(other, slot)| {
            *other != pair
                && slot.incoming.as_ref().is_some_and(|(p, until)| {
                    *until > Instant::now() && p.tag[..16] == profile.tag[..16]
                })
        }) {
            return Err(rejected());
        }
        let slot = slots.get_mut(&pair).ok_or_else(rejected)?;
        let now = Instant::now();
        let prefix = profile.tag[..16].try_into().map_err(|_| rejected())?;
        slot.recent.retain(|(_, until)| *until > now);
        if slot.recent.len() >= 64 || slot.recent.iter().any(|(tag, _)| tag == &prefix) {
            return Err(rejected());
        }
        slot.recent
            .push_back((prefix, now + Duration::from_secs(60)));
        slot.incoming = Some((Arc::new(profile), now + LIFETIME));
        Ok(())
    }

    /// Resolve a bounded, public identifier before verifying the private credential.
    pub fn lookup(&self, tag: &[u8]) -> io::Result<Ticket> {
        if !matches!(tag.len(), 16 | 32) {
            return Err(rejected());
        }
        let slots = self.0.lock().unwrap_or_else(|p| p.into_inner());
        slots
            .iter()
            .find_map(|(pair, slot)| {
                let (p, expiry) = slot.incoming.as_ref()?;
                (p.tag.starts_with(tag) && *expiry > Instant::now()).then(|| Ticket {
                    pair: *pair,
                    profile: p.clone(),
                })
            })
            .ok_or_else(rejected)
    }
    /// Consume only after successful wire authentication and before acknowledging the client.
    pub fn claim(&self, ticket: &Ticket) -> io::Result<()> {
        let mut slots = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let slot = slots.get_mut(&ticket.pair).ok_or_else(rejected)?;
        slot.incoming
            .take_if(|(p, until)| Arc::ptr_eq(p, &ticket.profile) && *until > Instant::now())
            .map(|_| ())
            .ok_or_else(rejected)
    }
    pub(crate) fn expire(&self) {
        for slot in self
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values_mut()
        {
            slot.incoming.take_if(|(_, until)| *until <= Instant::now());
        }
    }
}
pub(crate) fn rejected() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unknown or expired connection attempt",
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn attempts_rotate_and_a_delayed_claim_cannot_consume_a_replacement() {
        let registry = Profiles::default();
        let pair = (
            NetworkId::from_bytes([12; 32]),
            tsunagi::identity::DeviceIdentity::generate().endpoint_id(),
        );
        registry.0.lock().unwrap().insert(pair, Slot::default());
        let a = Profile::fresh();
        let tag = a.tag;
        registry.offer(pair, a).unwrap();
        let old = registry.lookup(&tag).unwrap();
        let b = Profile::fresh();
        assert_ne!(old.profile.tag, b.tag);
        assert_ne!(old.profile.secret, b.secret);
        let tag = b.tag;
        registry.offer(pair, b).unwrap();
        assert!(registry.claim(&old).is_err());
        let current = registry.lookup(&tag).unwrap();
        registry.claim(&current).unwrap();
        assert!(registry.claim(&current).is_err());
        assert!(registry.lookup(&tag).is_err());
        let duplicate = Profile {
            tag,
            secret: current.profile.secret,
            variant: current.profile.variant,
        };
        assert!(registry.offer(pair, duplicate).is_err());
    }

    #[test]
    fn wrong_network_expiry_and_retirement_reject_existing_tickets() {
        let registry = Profiles::default();
        let peer = tsunagi::identity::DeviceIdentity::generate().endpoint_id();
        let pair = (NetworkId::from_bytes([7; 32]), peer);
        let other = (NetworkId::from_bytes([8; 32]), peer);
        registry.0.lock().unwrap().insert(pair, Slot::default());
        assert!(registry.offer(other, Profile::fresh()).is_err());
        let offered = Profile::fresh();
        let tag = offered.tag;
        registry.offer(pair, offered).unwrap();
        let ticket = registry.lookup(&tag).unwrap();
        registry
            .0
            .lock()
            .unwrap()
            .get_mut(&pair)
            .unwrap()
            .incoming
            .as_mut()
            .unwrap()
            .1 = Instant::now();
        assert!(registry.lookup(&tag).is_err());
        assert!(registry.claim(&ticket).is_err());
        registry.expire();
        registry.0.lock().unwrap().remove(&pair);
        assert!(registry.claim(&ticket).is_err());
    }
}
