//! Wintun default routes cannot specify a preferred IPv4 source address.
use super::{Domains, SourceFlows, SourceMode};
use crate::BoxFuture;
use crate::overlay::{Cidr, OverlayError, TunDevice};
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard};

pub(crate) struct ExitSourceTun {
    device: Arc<dyn TunDevice>,
    state: Mutex<Option<State>>,
}

struct State {
    flows: SourceFlows,
    pending: std::vec::IntoIter<Bytes>,
}

impl std::fmt::Debug for ExitSourceTun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ExitSourceTun").field(&self.device).finish()
    }
}

impl ExitSourceTun {
    pub(crate) fn new(device: Arc<dyn TunDevice>) -> Self {
        Self {
            device,
            state: Mutex::default(),
        }
    }

    fn state(&self) -> MutexGuard<'_, Option<State>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl TunDevice for ExitSourceTun {
    fn name(&self) -> &str {
        self.device.name()
    }

    fn mtu(&self) -> u32 {
        self.device.mtu()
    }

    fn set_exit_source(&self, addresses: &[Cidr], source: Option<Ipv4Addr>) {
        let mut active = self.state();
        let domains = Domains::new(addresses, source, SourceMode::ExitOnly);
        if domains.aliases.len() < 2 || !source.is_some_and(|addr| domains.has(addr)) {
            *active = None;
            return;
        }
        if let Some(state) = active.as_mut() {
            if state.flows.domains != domains {
                state.flows.reconfigure(addresses, source, self.mtu());
                state.pending = Vec::new().into_iter();
            }
        } else {
            *active = Some(State {
                flows: SourceFlows::new(addresses, source, self.mtu(), SourceMode::ExitOnly),
                pending: Vec::new().into_iter(),
            });
        }
    }

    fn recv(&self) -> BoxFuture<'_, Option<Bytes>> {
        Box::pin(async {
            if let Some(part) = self.state().as_mut().and_then(|s| s.pending.next()) {
                return Some(part);
            }
            loop {
                let packet = self.device.recv().await?;
                let mut active = self.state();
                let Some(state) = active.as_mut() else {
                    return Some(packet);
                };
                state.pending = state.flows.outbound(packet).into_iter();
                if let Some(part) = state.pending.next() {
                    return Some(part);
                }
            }
        })
    }

    fn send(&self, packet: Bytes) -> BoxFuture<'_, Result<(), OverlayError>> {
        Box::pin(async move {
            let parts = self
                .state()
                .as_mut()
                .map(|s| s.flows.inbound(packet.clone()));
            if let Some(parts) = parts {
                for part in parts {
                    self.device.send(part).await?;
                }
                Ok(())
            } else {
                self.device.send(packet).await
            }
        })
    }
}
