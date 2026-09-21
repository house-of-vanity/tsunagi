//! The adapter between the plugin's view of a packet interface and the
//! host-management view.
//!
//! The plugin asks a [`TunFactory`] for a device and knows nothing else. This
//! factory answers by reconciling the host — creating the interface, fixing
//! up whatever an earlier run left behind, assigning the addresses — and
//! handing back the device that came out of it.

use std::sync::Arc;

use crate::BoxFuture;
use crate::overlay::OverlayError;

use super::super::tun::{TunDevice, TunFactory, TunRequest};
use super::{InterfacePlan, InterfaceProvisioner};

/// Turns a [`TunRequest`] into the plan for a host interface.
fn plan_for(request: &TunRequest) -> Result<InterfacePlan, OverlayError> {
    // Every address, because the plan is exhaustive: the provisioner adds
    // what is missing and removes what is not in it. Passing one network's
    // address would take every other network's off the host.
    Ok(InterfacePlan::new(
        request.name.clone(),
        request.mtu,
        request.addresses.clone(),
    ))
}

/// A [`TunFactory`] backed by an [`InterfaceProvisioner`].
#[derive(Debug)]
pub struct ManagedTunFactory {
    provisioner: Arc<dyn InterfaceProvisioner>,
}

impl ManagedTunFactory {
    /// Wraps a provisioner.
    pub fn new(provisioner: Arc<dyn InterfaceProvisioner>) -> Self {
        Self { provisioner }
    }

    /// The provisioner underneath.
    pub fn provisioner(&self) -> &Arc<dyn InterfaceProvisioner> {
        &self.provisioner
    }
}

impl TunFactory for ManagedTunFactory {
    fn name(&self) -> &str {
        self.provisioner.name()
    }

    /// It creates the interface on the host and holds it open.
    fn on_host(&self) -> bool {
        true
    }

    fn create<'a>(
        &'a self,
        request: TunRequest,
    ) -> BoxFuture<'a, Result<Arc<dyn TunDevice>, OverlayError>> {
        Box::pin(async move {
            let plan = plan_for(&request)?;
            let provisioned = self.provisioner.reconcile(&plan).await?;
            tracing::info!(
                interface = %plan.name,
                changes = %provisioned.changes.summary(),
                "overlay interface reconciled"
            );
            provisioned.device.ok_or_else(|| {
                // Reaching here would mean the interface already existed and
                // was held open by us, which cannot be true on the path that
                // creates a device.
                OverlayError::Other(format!(
                    "interface `{}` was reconciled but no device came back",
                    plan.name
                ))
            })
        })
    }

    fn reconfigure<'a>(&'a self, request: TunRequest) -> BoxFuture<'a, Result<(), OverlayError>> {
        Box::pin(async move {
            let plan = plan_for(&request)?;
            let provisioned = self.provisioner.reconcile(&plan).await?;
            if !provisioned.changes.is_empty() {
                tracing::info!(
                    interface = %plan.name,
                    changes = %provisioned.changes.summary(),
                    "overlay interface updated"
                );
            }
            Ok(())
        })
    }

    fn destroy<'a>(&'a self, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            match self.provisioner.remove(name).await {
                Ok(()) => tracing::info!(interface = %name, "overlay interface removed"),
                Err(err) => {
                    tracing::warn!(interface = %name, %err, "cannot remove the overlay interface")
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::net::Ipv4Addr;

    use super::super::super::config::Cidr;
    use super::super::{LinkKind, MockHost, MockProvisioner};
    use super::*;

    fn request(v4: Option<Ipv4Addr>) -> TunRequest {
        addressed(v4.into_iter().collect())
    }

    fn addressed(v4: Vec<Ipv4Addr>) -> TunRequest {
        TunRequest {
            name: "tsunfactory".into(),
            addresses: v4
                .into_iter()
                .map(|address| Cidr::new(address.into(), 24).unwrap())
                .collect(),
            mtu: 1280,
        }
    }

    #[tokio::test]
    async fn creating_a_device_provisions_the_host_and_returns_it() {
        let provisioner = Arc::new(MockProvisioner::default());
        let factory = ManagedTunFactory::new(provisioner.clone());

        let device = factory
            .create(request(Some(Ipv4Addr::new(10, 13, 37, 69))))
            .await
            .unwrap();
        assert_eq!(device.name(), "tsunfactory");
        assert_eq!(device.mtu(), 1280);

        let state = provisioner.host().get("tsunfactory").unwrap();
        assert_eq!(state.kind, LinkKind::Tun);
        assert_eq!(state.mtu, 1280);
        assert_eq!(state.addresses.len(), 1, "the overlay address is assigned");
    }

    #[tokio::test]
    async fn a_reallocated_address_is_applied_to_the_live_interface() {
        let provisioner = Arc::new(MockProvisioner::default());
        let factory = ManagedTunFactory::new(provisioner.clone());
        factory
            .create(request(Some(Ipv4Addr::new(10, 13, 37, 69))))
            .await
            .unwrap();

        factory
            .reconfigure(request(Some(Ipv4Addr::new(10, 13, 37, 70))))
            .await
            .unwrap();

        let state = provisioner.host().get("tsunfactory").unwrap();
        assert!(state.attached, "the interface was not recreated");
        let addresses: Vec<String> = state
            .addresses
            .iter()
            .map(|entry| entry.to_string())
            .collect();
        assert!(
            addresses.contains(&"10.13.37.70/24".to_string()),
            "{addresses:?}"
        );
        assert!(
            !addresses.contains(&"10.13.37.69/24".to_string()),
            "{addresses:?}"
        );
    }

    #[tokio::test]
    async fn destroying_takes_the_interface_off_the_host() {
        let provisioner = Arc::new(MockProvisioner::default());
        let factory = ManagedTunFactory::new(provisioner.clone());
        factory.create(request(None)).await.unwrap();

        factory.destroy("tsunfactory").await;
        assert!(provisioner.host().names().is_empty());
    }

    #[tokio::test]
    async fn a_host_that_cannot_be_provisioned_fails_the_create() {
        let host = MockHost::new();
        host.insert(
            "tsunfactory",
            super::super::InterfaceState {
                kind: LinkKind::Foreign("bridge".into()),
                attached: true,
                up: true,
                mtu: 1500,
                addresses: Vec::new(),
            },
        );
        let factory = ManagedTunFactory::new(Arc::new(MockProvisioner::new(host)));
        let err = factory.create(request(None)).await.unwrap_err();
        assert!(err.to_string().contains("bridge"), "{err}");
    }

    #[tokio::test]
    async fn every_network_s_address_reaches_the_host_not_just_the_first() {
        // One agent has one interface and a network apiece on it. Carrying
        // only the first address is carrying only the first network: the
        // rest have addresses the operating system has never heard of, and
        // their traffic goes nowhere while the status says all is well.
        let provisioner = Arc::new(MockProvisioner::default());
        let factory = ManagedTunFactory::new(provisioner.clone());
        factory
            .create(addressed(vec![
                Ipv4Addr::new(10, 13, 37, 69),
                Ipv4Addr::new(10, 156, 200, 116),
            ]))
            .await
            .unwrap();

        let state = provisioner.host().get("tsunfactory").unwrap();
        let addresses: Vec<String> = state
            .addresses
            .iter()
            .map(|entry| entry.to_string())
            .collect();
        assert!(
            addresses.contains(&"10.13.37.69/24".to_string()),
            "{addresses:?}"
        );
        assert!(
            addresses.contains(&"10.156.200.116/24".to_string()),
            "{addresses:?}"
        );

        // And leaving one network takes its address off, because the plan
        // is what the interface should carry and nothing else.
        factory
            .reconfigure(addressed(vec![Ipv4Addr::new(10, 13, 37, 69)]))
            .await
            .unwrap();
        let state = provisioner.host().get("tsunfactory").unwrap();
        let addresses: Vec<String> = state
            .addresses
            .iter()
            .map(|entry| entry.to_string())
            .collect();
        assert_eq!(addresses, vec!["10.13.37.69/24".to_string()]);
    }
}
