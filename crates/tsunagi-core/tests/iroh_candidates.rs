//! The local candidate filter must affect actual hole-punch addresses, not only publications.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use iroh::{
    Endpoint, RelayMode, TransportAddr,
    endpoint::{PortmapperConfig, presets},
};
use std::borrow::Cow;

#[tokio::test]
async fn direct_candidate_filter_changes_the_address_watch_used_by_connections() {
    let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let called = observed.clone();
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .portmapper_config(PortmapperConfig::Disabled)
        .net_report_config(iroh::NetReportConfig::minimal())
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        // Stand in for addresses on the agent's own overlay interface.
        .direct_addr_filter(iroh::address_lookup::AddrFilter::new(move |addrs| {
            if addrs
                .iter()
                .any(|addr| matches!(addr, TransportAddr::Ip(_)))
            {
                called.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            Cow::Owned(
                addrs
                    .iter()
                    .filter(|addr| !matches!(addr, TransportAddr::Ip(_)))
                    .cloned()
                    .collect(),
            )
        }))
        .bind()
        .await
        .unwrap();
    tsunagi::testing::wait_until("filter applied to actual bound candidates", || async {
        observed
            .load(std::sync::atomic::Ordering::Relaxed)
            .then_some(())
    })
    .await;
    assert!(
        !endpoint.bound_sockets().is_empty(),
        "real UDP sockets are still bound"
    );
    assert!(
        endpoint.addr().ip_addrs().next().is_none(),
        "excluded local paths never reach iroh's connection candidates"
    );
    endpoint.close().await;
}

#[tokio::test]
async fn carriers_exclude_the_kernel_assigned_interface_name_instead_of_the_requested_alias() {
    use std::sync::{Arc, Mutex};
    use tsunagi::dataplane::transport::DataCarrier;
    use tsunagi::dataplane::{PluginCapability, PluginError};
    use tsunagi::overlay::{MemoryTunFactory, OverlayError, TunDevice, TunFactory, TunRequest};
    use tsunagi::{BoxFuture, NetworkId};

    #[derive(Debug)]
    struct RenamingFactory(MemoryTunFactory);
    impl TunFactory for RenamingFactory {
        fn name(&self) -> &str {
            "kernel-name-test"
        }
        fn on_host(&self) -> bool {
            false
        }
        fn create<'a>(
            &'a self,
            mut request: TunRequest,
        ) -> BoxFuture<'a, Result<Arc<dyn TunDevice>, OverlayError>> {
            request.name = "kernel-assigned".into();
            self.0.create(request)
        }
        fn reconfigure<'a>(
            &'a self,
            request: TunRequest,
        ) -> BoxFuture<'a, Result<(), OverlayError>> {
            self.0.reconfigure(request)
        }
        fn destroy<'a>(&'a self, name: &'a str) -> BoxFuture<'a, ()> {
            self.0.destroy(name)
        }
    }
    #[derive(Debug, Default)]
    struct Carrier(Mutex<Option<String>>);
    impl DataCarrier for Carrier {
        fn protocol_id(&self) -> &str {
            "candidate-test"
        }
        fn protocol_version(&self) -> u16 {
            1
        }
        fn on_interface_ready(&self, name: &str) {
            *self.0.lock().unwrap() = Some(name.into());
        }
        fn local_capability(&self, _: NetworkId) -> Result<Option<PluginCapability>, PluginError> {
            Ok(None)
        }
        fn on_peer_capability(
            &self,
            _: NetworkId,
            _: iroh::EndpointId,
            _: &PluginCapability,
        ) -> Result<(), PluginError> {
            Ok(())
        }
        fn on_peer_gone(&self, _: NetworkId, _: iroh::EndpointId) {}
        fn on_network_deactivated(&self, _: NetworkId) {}
    }
    let root = tempfile::TempDir::new().unwrap();
    let discovery = tsunagi::discovery::SharedMemoryDiscovery::new();
    let carrier = Arc::new(Carrier::default());
    let config = tsunagi::testing::config_with(root.path(), &discovery)
        .with_interface(
            Arc::new(RenamingFactory(MemoryTunFactory::new())),
            "requested-alias",
            1280,
        )
        .with_carrier(carrier.clone());
    let agent = tsunagi::Agent::spawn(config).await.unwrap();
    assert_eq!(agent.overlay().unwrap().interface, "kernel-assigned");
    assert_eq!(
        carrier.0.lock().unwrap().as_deref(),
        Some("kernel-assigned")
    );
    agent.shutdown().await;
}
