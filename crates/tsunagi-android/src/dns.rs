//! Device-local split DNS. Only questions outside the signed mesh zones reach Android's resolver.
use simple_dns::{Packet, PacketFlag, RCODE};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::sync::{Semaphore, watch};
use tsunagi::dns::{
    Zones,
    server::{MAX_MESSAGE_LEN, Resolution, parse_message, resolve},
};

#[cfg(unix)]
pub(crate) mod stack;

type Upstream = dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync;

/// One view of all joined zones, shared across TUN replacements.
#[derive(Clone)]
pub struct Resolver {
    zones: watch::Sender<Option<Arc<Zones>>>,
    listening: watch::Sender<Option<Ipv4Addr>>,
    upstream: Arc<Upstream>,
    pending: Arc<Semaphore>,
}

impl Resolver {
    /// The platform callback resolves a wire question on the selected physical network.
    pub fn new(upstream: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static) -> Self {
        Self {
            zones: watch::channel(None).0,
            listening: watch::channel(None).0,
            upstream: Arc::new(upstream),
            pending: Arc::new(Semaphore::new(16)),
        }
    }

    /// Withhold forwarding while configured zones are loading or changing.
    pub fn replace(&self, zones: Option<Zones>) {
        self.zones.send_replace(zones.map(Arc::new));
    }

    #[cfg(unix)]
    pub(crate) fn publish(&self, address: Option<Ipv4Addr>) {
        self.listening.send_replace(address);
    }

    pub(crate) fn refresh(&self, networks: &[tsunagi::NetworkStatus]) -> tsunagi::ipc::DnsReport {
        let view = tsunagi::dns::RosterZones::from_networks(networks);
        let names = view.zones.names() as u32;
        self.replace(Some(view.zones));
        let address = *self.listening.borrow();
        tsunagi::ipc::DnsReport {
            listening: address.map(|ip| format!("{ip}:53")).into_iter().collect(),
            publish_error: (address.is_none() && !view.labels.is_empty())
                .then(|| "Waiting for a VPN interface with a DNS address.".into()),
            zones: view.labels,
            zone_warnings: view.warnings,
            names,
            ..Default::default()
        }
    }

    /// Answer a local DNS request. Slow public lookups never block a mesh answer.
    pub async fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() > MAX_MESSAGE_LEN {
            return None;
        }
        let zones = self.zones.borrow().clone();
        let Some(zones) = zones else {
            let question = parse_message(query)?;
            if question.has_flags(PacketFlag::RESPONSE) {
                return None;
            }
            return error_reply(&question, RCODE::ServerFailure);
        };
        match resolve(&zones, query)? {
            Resolution::Local(reply) => Some(reply),
            Resolution::Outside(_) => {
                let question = parse_message(query)?;
                if let Ok(permit) = self.pending.clone().try_acquire_owned() {
                    let upstream = self.upstream.clone();
                    let wire = query.to_vec();
                    let job = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        upstream(&wire)
                    });
                    if let Ok(Ok(Some(mut wire))) =
                        tokio::time::timeout(Duration::from_secs(5), job).await
                        && wire.len() <= usize::from(u16::MAX)
                        && parse_message(&wire).is_some_and(|p| {
                            let [received] = p.questions.as_slice() else {
                                return false;
                            };
                            let sent = &question.questions[0]; // Resolution::Outside has exactly one IN question.
                            p.has_flags(PacketFlag::RESPONSE)
                                && received.qtype == sent.qtype
                                && received.qclass == sent.qclass
                                && received
                                    .qname
                                    .to_string()
                                    .eq_ignore_ascii_case(&sent.qname.to_string())
                        })
                    {
                        // Android's upstream transaction may have used its own ID.
                        wire[..2].copy_from_slice(&question.id().to_be_bytes());
                        return Some(wire);
                    }
                }
                error_reply(&question, RCODE::ServerFailure)
            }
        }
    }
}

fn error_reply(query: &Packet<'_>, code: RCODE) -> Option<Vec<u8>> {
    let mut answer = Packet::new_reply(query.id());
    answer.questions.clone_from(&query.questions);
    if query.has_flags(PacketFlag::RECURSION_DESIRED) {
        answer.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    answer.set_flags(PacketFlag::RECURSION_AVAILABLE);
    *answer.rcode_mut() = code;
    answer.build_bytes_vec_compressed().ok()
}
