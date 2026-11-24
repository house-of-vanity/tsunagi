//! Compare one alternative per peer while normal traffic stays on the incumbent.
//! The elected dialler chooses for both directions. Each decision names the
//! exact two health profiles, so delayed messages cannot retire a reopened link.
use super::{ControlMessage, EndpointId, Event, PacketLink, PluginCapability, Runtime};
use crate::dataplane::transport::{LinkQuality, TransportPayload};
use std::time::{Duration, Instant};

pub(super) const PROTOCOL: &str = "link-choice";
const RETRY: Duration = Duration::from_secs(3);
const NEXT_TRIAL: Duration = Duration::from_secs(120);
const MIN_WINDOW: Duration = Duration::from_secs(6);
// Allow a full rolling health window to replace probes sent before the
// responder installed its profile. Persistent loss still disqualifies a trial.
const MAX_WINDOW: Duration = Duration::from_secs(30);

pub(super) fn capability() -> PluginCapability {
    PluginCapability {
        protocol: PROTOCOL.into(),
        version: 1,
        enabled: true,
        data: Vec::new(),
    }
}

fn supports_choice(caps: &[PluginCapability]) -> bool {
    caps.iter()
        .any(|c| c.enabled && c.protocol == PROTOCOL && c.version == 1)
}

/// None keeps measuring on the alternative while user traffic stays on the incumbent.
fn promotion_decision(age: Duration, measured: Option<(LinkQuality, LinkQuality)>) -> Option<bool> {
    if age < MIN_WINDOW {
        return None;
    }
    let Some((current, alternative)) = measured.filter(|(current, alternative)| {
        current.samples >= 5 && alternative.samples >= 5 && alternative.losses == 0
    }) else {
        return (age >= MAX_WINDOW).then_some(false);
    };
    let gain = current.rtt.saturating_sub(alternative.rtt);
    Some(gain >= (current.rtt / 5).max(Duration::from_millis(5)))
}

/// Fixed-size identifiers from the two privately negotiated health profiles.
/// The responder echoes this value after accepting a decision.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Choice {
    keep: [u8; 16],
    retire: [u8; 16],
}

struct Trial {
    protocol: String,
    started: Instant,
    decision: Option<Choice>,
    retry_at: Instant,
}

pub(super) struct Schedule {
    next: Instant,
    cursor: usize,
    trial: Option<Trial>,
}

impl Schedule {
    pub(super) fn is_trial(&self, protocol: &str) -> bool {
        self.trial
            .as_ref()
            .is_some_and(|trial| trial.protocol == protocol)
    }

    /// The responder can close the losing link before its acknowledgement
    /// arrives. Only an exact generation match makes this a planned closure.
    pub(super) fn retiring(&self, profile: Option<[u8; 16]>) -> bool {
        self.trial
            .as_ref()
            .and_then(|trial| trial.decision)
            .is_some_and(|choice| Some(choice.retire) == profile)
    }
}

impl Runtime {
    pub(super) fn link_installed(&mut self, peer: EndpointId) {
        if self.local_id.as_bytes() >= peer.as_bytes() || self.params.carriers.len() < 2 {
            return;
        }
        let now = Instant::now();
        let jitter = (peer.as_bytes()[0] ^ self.network_id.as_bytes()[0]) % 6;
        let schedule = self.comparisons.entry(peer).or_insert(Schedule {
            next: now + Duration::from_secs(12 + u64::from(jitter)),
            cursor: 0,
            trial: None,
        });
        if let Some(trial) = &mut schedule.trial {
            // Any replacement invalidates an outstanding decision naming the
            // previous pair of profiles. Compare both current links afresh.
            trial.decision = None;
            trial.started = now;
            trial.retry_at = now;
        }
    }

    /// At most two alternatives per network are opened or measured at once.
    /// Waiting for a peer to acknowledge a decision uses no measurement slot. Old peers
    /// keep the original single-carrier behaviour without a wire upgrade.
    pub(super) fn next_comparison(
        &mut self,
        served: &[(String, u16)],
        now: Instant,
    ) -> Option<(EndpointId, String)> {
        if !supports_choice(&self.local_capabilities)
            || self
                .comparisons
                .values()
                .filter_map(|s| s.trial.as_ref())
                .filter(|trial| trial.decision.is_none())
                .count()
                >= 2
        {
            return None;
        }
        let (peer, index) =
            self.comparisons
                .iter()
                .filter_map(|(peer, schedule)| {
                    if schedule.next > now
                        || schedule.trial.is_some()
                        || self.no_direct_data(*peer)
                        || self.opening.iter().any(|(id, _)| id == peer)
                    {
                        return None;
                    }
                    let session = self.sessions.get(peer)?;
                    if !supports_choice(&session.capabilities)
                        || self.hub.direct_kinds(*peer).len() != 1
                    {
                        return None;
                    }
                    let index = (0..served.len())
                        .map(|n| (n + schedule.cursor) % served.len())
                        .find(|i| {
                            let (name, version) = &served[*i];
                            let key = (*peer, name.clone());
                            !self.links.contains_key(&key)
                                && self
                                    .protocol_dial_states
                                    .get(&key)
                                    .is_none_or(|s| s.cooldown_until <= now)
                                && session.capabilities.iter().any(|c| {
                                    c.enabled && &c.protocol == name && &c.version == version
                                })
                        })?;
                    Some((schedule.next, *peer, index))
                })
                .min()
                .map(|(_, peer, index)| (peer, index))?;
        let schedule = self.comparisons.get_mut(&peer)?;
        let protocol = served[index].0.clone();
        schedule.cursor = index + 1;
        schedule.trial = Some(Trial {
            protocol: protocol.clone(),
            started: now,
            decision: None,
            retry_at: now,
        });
        Some((peer, protocol))
    }

    pub(super) fn finish_comparison(&mut self, peer: EndpointId) {
        if let Some(schedule) = self.comparisons.get_mut(&peer) {
            schedule.trial = None;
            schedule.next = Instant::now() + NEXT_TRIAL;
        }
    }

    pub(super) fn review_comparisons(&mut self) {
        let peers: Vec<_> = self
            .comparisons
            .iter()
            .filter(|(_, s)| s.trial.is_some())
            .map(|(peer, _)| *peer)
            .collect();
        for peer in peers {
            self.review_trial(peer);
        }
    }

    fn review_trial(&mut self, peer: EndpointId) {
        let Some(trial) = self.comparisons.get(&peer).and_then(|s| s.trial.as_ref()) else {
            return;
        };
        let key = (peer, trial.protocol.clone());
        if self.opening.contains(&key) {
            return;
        }
        let kinds = self.hub.direct_kinds(peer);
        if kinds.len() < 2 || !self.links.contains_key(&key) {
            self.finish_comparison(peer);
            return;
        }
        let now = Instant::now();
        if now < trial.retry_at {
            return;
        }
        let choice = if let Some(choice) = trial.decision {
            choice
        } else {
            let Some(other) = kinds.iter().find(|kind| **kind != trial.protocol) else {
                return;
            };
            let Some(current) = self.links.get(&(peer, other.clone())) else {
                return;
            };
            let Some(candidate) = self.links.get(&key) else {
                return;
            };
            let age = now.duration_since(trial.started);
            let measured = current.quality().zip(candidate.quality());
            let Some(promote) = promotion_decision(age, measured) else {
                return;
            };
            tracing::debug!(peer = %peer.fmt_short(), incumbent = %other, candidate = %trial.protocol, ?measured, promote, "compared data carriers");
            let (winner, loser) = if promote {
                (candidate, current)
            } else {
                (current, candidate)
            };
            let (Some(keep), Some(retire)) = (winner.profile_id(), loser.profile_id()) else {
                return;
            };
            self.hub
                .prefer_direct(peer, if promote { &trial.protocol } else { other });
            Choice { keep, retire }
        };
        if let Some(trial) = self
            .comparisons
            .get_mut(&peer)
            .and_then(|s| s.trial.as_mut())
        {
            trial.decision = Some(choice);
            trial.retry_at = now + RETRY;
        }
        self.send_choice(peer, choice);
    }

    fn send_choice(&mut self, peer: EndpointId, choice: Choice) {
        if let Ok(bytes) = postcard::to_stdvec(&choice) {
            let _ = self.send_to(
                peer,
                ControlMessage::Transport {
                    protocol: PROTOCOL.into(),
                    payload: TransportPayload::new(bytes),
                },
            );
        }
    }

    pub(super) fn receive_choice(&mut self, peer: EndpointId, payload: &[u8]) {
        if payload.len() != 32 {
            return;
        }
        let Ok(choice) = postcard::from_bytes::<Choice>(payload) else {
            return;
        };
        if choice.keep == choice.retire
            || !supports_choice(&self.local_capabilities)
            || !self
                .sessions
                .get(&peer)
                .is_some_and(|s| supports_choice(&s.capabilities))
        {
            return;
        }
        let dialler = self.local_id.as_bytes() < peer.as_bytes();
        if dialler
            && self
                .comparisons
                .get(&peer)
                .and_then(|s| s.trial.as_ref())
                .and_then(|t| t.decision)
                != Some(choice)
        {
            return;
        }
        let find = |profile| {
            self.links
                .iter()
                .find(|((id, _), link)| {
                    *id == peer && !link.is_closed() && link.profile_id() == Some(profile)
                })
                .map(|((_, kind), _)| kind.clone())
        };
        let Some(winner) = find(choice.keep) else {
            return;
        };
        let loser = find(choice.retire);
        self.hub.prefer_direct(peer, &winner);
        if let Some(kind) = loser {
            self.hub.clear_direct(peer, &kind);
            if let Some(link) = self.links.remove(&(peer, kind.clone())) {
                link.close();
                self.emit(Event::DataLinkDown {
                    network: self.network_id,
                    peer,
                    protocol: kind,
                    reason: format!("carrier comparison kept {winner}"),
                });
            }
        }
        if dialler {
            self.finish_comparison(peer);
        } else {
            self.send_choice(peer, choice);
        }
        self.announce_reach(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measurement(ms: u64, samples: usize, losses: usize) -> LinkQuality {
        LinkQuality {
            rtt: Duration::from_millis(ms),
            samples,
            losses,
            observed_at: Instant::now(),
        }
    }

    #[test]
    fn a_loss_during_profile_installation_can_age_out_before_deciding() {
        let observed =
            |samples, losses| Some((measurement(200, 20, 0), measurement(30, samples, losses)));
        assert_eq!(promotion_decision(MIN_WINDOW, observed(5, 1)), None);
        assert_eq!(
            promotion_decision(Duration::from_secs(24), observed(20, 0)),
            Some(true)
        );
        assert_eq!(promotion_decision(MAX_WINDOW, observed(18, 2)), Some(false));
        assert_eq!(promotion_decision(MAX_WINDOW, observed(4, 0)), Some(false));
        assert_eq!(promotion_decision(MIN_WINDOW / 2, observed(5, 0)), None);
    }

    #[test]
    fn promote_only_a_sampled_reliable_and_materially_faster_path() {
        let better = |current: &LinkQuality, candidate: &LinkQuality| {
            promotion_decision(MAX_WINDOW, Some((*current, *candidate))) == Some(true)
        };
        let current = measurement(350, 20, 1);
        assert!(better(&current, &measurement(60, 6, 0)));
        assert!(!better(&current, &measurement(60, 1, 0)));
        assert!(!better(&current, &measurement(60, 6, 2)));
        assert!(!better(&measurement(61, 20, 0), &measurement(59, 10, 0)));
        assert!(!better(&measurement(10, 20, 0), &measurement(7, 10, 0)));
        assert!(!better(&measurement(8, 2, 0), &measurement(1, 6, 0)));
    }
}
