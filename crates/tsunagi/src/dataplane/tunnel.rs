//! Generic harness for IP tunnel plugins.
//!
//! Implementing [`super::IpPlugin`] directly requires managing per-peer background
//! tasks, synchronization, packet queues, and graceful shutdown.
//!
//! [`TunnelCodec`] provides a simplified interface where a plugin author only
//! defines cryptographic transformation and handshake payloads.
//! [`GenericTunnelPlugin`] adapts any [`TunnelCodec`] into a full [`super::IpPlugin`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use bytes::Bytes;
use iroh::EndpointId;
use tokio::task::JoinHandle;

use super::{IpPlugin, PluginCapability, PluginContext, PluginError, ProtocolOption, SharedLink};
use crate::BoxFuture;
use crate::identity::NetworkId;

/// The simplified contract for an IP tunnel protocol implementation.
///
/// Implementors only handle key announcements, link lifecycle events,
/// and packet encrypt/decrypt. Concurrency and task management are handled
/// by [`GenericTunnelPlugin`].
pub trait TunnelCodec: Send + Sync + 'static {
    /// Protocol identifier, e.g. `tcp-tls`.
    fn protocol_id(&self) -> &str;

    /// Protocol wire version.
    fn protocol_version(&self) -> u16;

    /// Options accepted by the protocol.
    fn options(&self) -> &'static [ProtocolOption] {
        &[]
    }

    /// Generates local capability announcement data for a network.
    fn local_capability_data(&self, network: NetworkId) -> Result<Vec<u8>, PluginError>;

    /// Handles a peer's announced capability payload.
    fn on_peer_capability_data(
        &self,
        network: NetworkId,
        peer: EndpointId,
        data: &[u8],
    ) -> Result<(), PluginError>;

    /// Called when an authenticated link to a peer is established.
    fn on_peer_link_up(&self, network: NetworkId, peer: EndpointId, link: &SharedLink) {
        let _ = (network, peer, link);
    }

    /// Called when a peer goes away.
    fn on_peer_down(&self, network: NetworkId, peer: EndpointId) {
        let _ = (network, peer);
    }

    /// Encrypts an outbound IP packet into a payload to send over the link.
    fn encrypt(
        &self,
        network: NetworkId,
        peer: EndpointId,
        packet: &[u8],
    ) -> Result<Bytes, PluginError>;

    /// Decrypts an inbound payload from the link into an IP packet.
    fn decrypt(
        &self,
        network: NetworkId,
        peer: EndpointId,
        payload: &[u8],
    ) -> Result<Bytes, PluginError>;

    /// Called during shutdown.
    fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

/// Generic wrapper that turns a [`TunnelCodec`] into a full [`IpPlugin`].
pub struct GenericTunnelPlugin<C: TunnelCodec> {
    codec: Arc<C>,
    context: Mutex<Option<PluginContext>>,
    links: RwLock<HashMap<(NetworkId, EndpointId), SharedLink>>,
    tasks: Mutex<HashMap<(NetworkId, EndpointId), JoinHandle<()>>>,
}

impl<C: TunnelCodec> GenericTunnelPlugin<C> {
    /// Wraps `codec` into an [`IpPlugin`].
    pub fn new(codec: C) -> Self {
        Self {
            codec: Arc::new(codec),
            context: Mutex::new(None),
            links: RwLock::new(HashMap::new()),
            tasks: Mutex::new(HashMap::new()),
        }
    }

    /// Returns a reference to the underlying codec.
    pub fn codec(&self) -> &C {
        &self.codec
    }

    /// Returns the active peers with established data links for a network.
    pub fn active_peers(&self, network: NetworkId) -> Vec<(EndpointId, String)> {
        let guard = match self.links.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard
            .iter()
            .filter(|((net, _), _)| *net == network)
            .map(|((_, peer), link)| (*peer, link.path_description()))
            .collect()
    }
}

impl<C: TunnelCodec> std::fmt::Debug for GenericTunnelPlugin<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenericTunnelPlugin")
            .field("protocol_id", &self.codec.protocol_id())
            .field("protocol_version", &self.codec.protocol_version())
            .finish()
    }
}

impl<C: TunnelCodec> IpPlugin for GenericTunnelPlugin<C> {
    fn protocol_id(&self) -> &str {
        self.codec.protocol_id()
    }

    fn protocol_version(&self) -> u16 {
        self.codec.protocol_version()
    }

    fn options(&self) -> &'static [ProtocolOption] {
        self.codec.options()
    }

    fn attach(&self, context: PluginContext) {
        if let Ok(mut guard) = self.context.lock() {
            *guard = Some(context);
        }
    }

    fn local_capability(
        &self,
        network: NetworkId,
    ) -> Result<Option<PluginCapability>, PluginError> {
        let data = self.codec.local_capability_data(network)?;
        Ok(Some(PluginCapability {
            protocol: self.codec.protocol_id().to_string(),
            version: self.codec.protocol_version(),
            enabled: true,
            data,
        }))
    }

    fn on_peer_capability(
        &self,
        network: NetworkId,
        peer: EndpointId,
        capability: &PluginCapability,
    ) -> Result<(), PluginError> {
        if capability.protocol != self.codec.protocol_id() {
            return Ok(());
        }
        self.codec
            .on_peer_capability_data(network, peer, &capability.data)
    }

    fn carry(&self, network: NetworkId, peer: EndpointId, packet: bytes::Bytes) -> bool {
        let link = {
            let guard = match self.links.read() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.get(&(network, peer)).cloned()
        };

        let Some(link) = link else {
            return false;
        };

        match self.codec.encrypt(network, peer, &packet) {
            Ok(ciphertext) => link.send(ciphertext).is_ok(),
            Err(err) => {
                tracing::debug!(%peer, %err, "tunnel encrypt failed");
                false
            }
        }
    }

    fn on_peer_link(&self, network: NetworkId, peer: EndpointId, link: SharedLink) {
        {
            let mut guard = match self.links.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.insert((network, peer), Arc::clone(&link));
        }

        self.codec.on_peer_link_up(network, peer, &link);

        let codec = Arc::clone(&self.codec);
        let sink = match self.context.lock() {
            Ok(g) => g.as_ref().map(|ctx| ctx.packet_sink()),
            Err(p) => p.into_inner().as_ref().map(|ctx| ctx.packet_sink()),
        };

        let rx_link = Arc::clone(&link);
        let handle = tokio::spawn(async move {
            while let Some(payload) = rx_link.recv().await {
                match codec.decrypt(network, peer, &payload) {
                    Ok(packet) => {
                        if let Some(ref sink) = sink {
                            sink.deliver(network, peer, packet).await;
                        }
                    }
                    Err(err) => {
                        tracing::debug!(%peer, %err, "tunnel decrypt failed");
                    }
                }
            }
        });

        let mut guard = match self.tasks.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(old) = guard.insert((network, peer), handle) {
            old.abort();
        }
    }

    fn on_peer_gone(&self, network: NetworkId, peer: EndpointId) {
        {
            let mut guard = match self.tasks.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let Some(task) = guard.remove(&(network, peer)) {
                task.abort();
            }
        }
        {
            let mut guard = match self.links.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.remove(&(network, peer));
        }
        self.codec.on_peer_down(network, peer);
    }

    fn on_network_deactivated(&self, network: NetworkId) {
        let keys_to_remove: Vec<(NetworkId, EndpointId)> = {
            let guard = match self.tasks.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard
                .keys()
                .filter(|(net, _)| *net == network)
                .copied()
                .collect()
        };

        {
            let mut guard = match self.tasks.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            for key in &keys_to_remove {
                if let Some(task) = guard.remove(key) {
                    task.abort();
                }
            }
        }

        {
            let mut guard = match self.links.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.retain(|(net, _), _| *net != network);
        }
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut tasks = Vec::new();
            {
                let mut guard = match self.tasks.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                for (_, task) in guard.drain() {
                    tasks.push(task);
                }
            }
            for task in tasks {
                task.abort();
            }
            self.codec.shutdown().await;
        })
    }
}
