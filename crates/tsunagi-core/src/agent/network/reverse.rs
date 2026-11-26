//! The elected opener grants one bounded reverse dial over authenticated control.
use super::{ControlMessage, EndpointId, LinkOutcome, PluginCapability, Runtime};
use crate::dataplane::transport::{DataCarrier, PacketLink, TransportPayload};
use std::time::{Duration, Instant};

pub(super) const PROTOCOL: &str = "link-reverse";

pub(super) fn capability() -> PluginCapability {
    PluginCapability {
        protocol: PROTOCOL.into(),
        version: 1,
        enabled: true,
        data: Vec::new(),
    }
}

impl Runtime {
    fn mutual_carrier(&self, peer: EndpointId, name: &str) -> Option<&dyn DataCarrier> {
        let caps = &self.sessions.get(&peer)?.capabilities;
        self.params
            .carriers
            .iter()
            .find(|c| {
                c.protocol_id() == name
                    && caps.iter().any(|cap| {
                        cap.enabled && cap.protocol == name && cap.version == c.protocol_version()
                    })
            })
            .map(|c| c.as_ref())
    }

    pub(super) fn can_reverse(&self, peer: EndpointId, protocol: &str) -> bool {
        self.mutual_carrier(peer, protocol)
            .is_some_and(|c| c.supports_reverse_dial())
            && self.sessions.get(&peer).is_some_and(|s| {
                s.capabilities
                    .iter()
                    .any(|c| c.enabled && c.protocol == PROTOCOL && c.version == 1)
            })
    }

    pub(super) fn send_reverse(
        &mut self,
        peer: EndpointId,
        protocol: &str,
        token: u64,
        request: bool,
    ) -> bool {
        let Ok(bytes) = postcard::to_stdvec(&(request, token, protocol)) else {
            return false;
        };
        self.send_to(
            peer,
            ControlMessage::Transport {
                protocol: PROTOCOL.into(),
                payload: TransportPayload::new(bytes),
            },
        )
        .is_ok()
    }

    pub(super) fn ask_for_reverse(&mut self, attempt: &LinkOutcome) -> bool {
        let peer = attempt.peer;
        let protocol = &attempt.protocol;
        let generation = attempt.generation;
        if self.local_id >= peer
            || !self.can_reverse(peer, protocol)
            || !self.send_reverse(peer, protocol, generation, true)
        {
            return false;
        }
        let key = (peer, protocol.clone());
        self.reverse_dials.insert(key.clone(), generation);
        let tx = self.link_results_tx.clone();
        let protocol = protocol.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(12)).await;
            let _ = tx
                .send(LinkOutcome {
                    generation,
                    peer,
                    protocol,
                    result: Err("reverse TCP dial timed out".into()),
                })
                .await;
        });
        self.link_tasks.insert(key, task.abort_handle());
        true
    }

    pub(super) fn receive_reverse(&mut self, peer: EndpointId, payload: &[u8]) {
        let Ok((request, generation, protocol)) =
            postcard::from_bytes::<(bool, u64, &str)>(payload)
        else {
            return;
        };
        if protocol.len() > crate::dataplane::MAX_PROTOCOL_ID_LEN
            || !self.can_reverse(peer, protocol)
        {
            return;
        }
        let key = (peer, protocol.to_owned());
        if request && peer < self.local_id {
            if self.opening.contains(&key) || self.links.get(&key).is_some_and(|l| !l.is_closed()) {
                return;
            }
            if self.no_direct_data(peer)
                || self
                    .protocol_dial_states
                    .get(&key)
                    .is_some_and(|s| s.cooldown_until > Instant::now())
            {
                self.send_reverse(peer, protocol, generation, false);
                return;
            }
            self.reverse_dials.insert(key, generation);
            self.start_link_attempt(peer, protocol.to_owned(), false);
        } else if !request
            && self.local_id < peer
            && self.reverse_dials.get(&key) == Some(&generation)
        {
            if let Some(task) = self.link_tasks.remove(&key) {
                task.abort();
            }
            self.handle_link_result(LinkOutcome {
                generation,
                peer,
                protocol: protocol.into(),
                result: Err("neither TCP dial direction succeeded".into()),
            });
        }
    }
}
