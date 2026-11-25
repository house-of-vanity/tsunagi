//! Each ordered stream keeps a cursor into the latest signed state. A slow or
//! reconnecting peer can catch up without a per-peer backlog of signed frames.
use super::{ControlMessage, EndpointId, MAX_RETIREMENT_LEN, Runtime};
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

/// The stable identity of a signed object, including tombstones.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SyncKey {
    Claim(EndpointId),
    Retirement(EndpointId),
    Vip(String),
}

/// One entry per stored object, regardless of its edit count or the number of
/// peers. Revisions are local scheduling information, never persisted or sent.
#[derive(Default)]
pub(super) struct Changes {
    latest: u64,
    revisions: BTreeMap<SyncKey, u64>,
    order: BTreeMap<u64, SyncKey>,
}

impl Changes {
    fn note(&mut self, key: SyncKey) {
        self.latest += 1;
        if let Some(previous) = self.revisions.insert(key.clone(), self.latest) {
            self.order.remove(&previous);
        }
        self.order.insert(self.latest, key);
    }

    fn after(&self, cursor: u64) -> impl Iterator<Item = (u64, &SyncKey)> {
        self.order
            .range((Excluded(cursor), Unbounded))
            .map(|(&revision, key)| (revision, key))
    }
}

impl Runtime {
    pub(super) fn index_stored_state(&mut self) {
        for record in self.state.records() {
            if let Ok(author) = record.author_id() {
                self.changes.note(SyncKey::Claim(author));
            }
        }
        for marker in self.state.retirements() {
            if let Ok(target) = marker.target.author_id() {
                self.changes.note(SyncKey::Retirement(target));
            }
        }
        for id in self.params.vips.ids() {
            self.changes.note(SyncKey::Vip(id));
        }
    }

    pub(super) fn share_changes(&mut self, keys: impl IntoIterator<Item = SyncKey>) -> usize {
        for key in keys {
            self.changes.note(key);
        }
        self.params.roster_changed.send_replace(());
        self.flush_updates();
        self.sessions
            .values()
            .filter(|session| session.state_sent == self.changes.latest)
            .count()
    }

    pub(super) fn flush_updates(&mut self) {
        let peers: Vec<_> = self
            .sessions
            .values()
            .filter(|s| s.state_sent < self.changes.latest)
            .map(|s| s.peer)
            .collect();
        for peer in peers {
            self.flush_peer(peer);
        }
    }

    pub(super) fn flush_peer(&mut self, peer: EndpointId) {
        // A retirement contains a signed claim plus a second signature, so its
        // size bound also covers a claim. VIPs are validated as complete frames.
        let limits = &self.params.limits;
        let batch = (limits.max_frame_len.saturating_sub(128) / MAX_RETIREMENT_LEN)
            .max(1)
            .min(limits.max_state_records.max(1));
        while let Some(session) = self.sessions.get(&peer) {
            if session.outbound.capacity() == 0 {
                break;
            }
            let cursor = session.state_sent;
            let Some((mut through, first)) = self.changes.after(cursor).next() else {
                break;
            };
            let message = {
                let pending = self.changes.after(cursor).take(batch);
                match first {
                    SyncKey::Claim(_) => ControlMessage::State {
                        records: pending
                            .map_while(|(revision, key)| {
                                let SyncKey::Claim(id) = key else { return None };
                                through = revision;
                                self.state.get(id).cloned()
                            })
                            .collect(),
                    },
                    SyncKey::Retirement(_) => ControlMessage::Retirements {
                        markers: pending
                            .map_while(|(revision, key)| {
                                let SyncKey::Retirement(id) = key else {
                                    return None;
                                };
                                through = revision;
                                self.state.retirement_of(id).cloned()
                            })
                            .collect(),
                    },
                    SyncKey::Vip(id) => ControlMessage::Vips {
                        entries: self.params.vips.entries(id),
                    },
                }
            };
            if self.send_to(peer, message).is_err() {
                break;
            }
            if let Some(session) = self.sessions.get_mut(&peer) {
                session.state_sent = through;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slow_and_returning_sessions_each_get_the_latest_revision() {
        let mut index = Changes::default();
        let first = SyncKey::Vip("first".into());
        let second = SyncKey::Vip("second".into());
        index.note(first.clone());
        let sent = index.latest;
        index.note(second.clone());
        index.note(first.clone());
        for cursor in [0, sent] {
            let pending: Vec<_> = index.after(cursor).map(|(_, key)| key.clone()).collect();
            assert_eq!(pending, [second.clone(), first.clone()]);
        }
        assert_eq!(index.after(index.latest).count(), 0);
    }
}
