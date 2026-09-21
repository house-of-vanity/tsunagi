//! An in-memory host, so provisioning is tested without touching this one.
//!
//! [`MockHost`] is a pretend `/sys/class/net`: a test can seed it with the
//! leftovers of a crashed run, or with somebody else's bridge, then check
//! what the provisioner did about it. It is also what the platforms that have
//! no provisioner yet are wired to in their own tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::BoxFuture;
use crate::dataplane::PluginError;

use super::super::config::Cidr;
use super::super::tun::{MemoryTun, MemoryTunFactory, TunFactory, TunRequest};
use super::{
    Changes, InterfacePlan, InterfaceProvisioner, InterfaceState, LinkKind, Provisioned,
    plan_changes,
};

/// A pretend host with interfaces on it.
#[derive(Debug, Clone, Default)]
pub struct MockHost {
    links: Arc<Mutex<HashMap<String, InterfaceState>>>,
}

impl MockHost {
    /// An empty host.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, InterfaceState>> {
        match self.links.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Puts an interface on the host.
    pub fn insert(&self, name: impl Into<String>, state: InterfaceState) {
        self.lock().insert(name.into(), state);
    }

    /// Seeds the leftovers of a run that died: a TUN nobody holds open, still
    /// carrying whatever addresses it had.
    pub fn insert_stale_tun(&self, name: impl Into<String>, addresses: Vec<Cidr>) {
        self.insert(
            name,
            InterfaceState {
                kind: LinkKind::Tun,
                attached: false,
                up: true,
                mtu: 1280,
                addresses,
            },
        );
    }

    /// The state of an interface, if it exists.
    pub fn get(&self, name: &str) -> Option<InterfaceState> {
        self.lock().get(name).cloned()
    }

    /// The names currently on the host.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.lock().keys().cloned().collect();
        names.sort();
        names
    }
}

/// Applies plans to a [`MockHost`].
#[derive(Debug, Clone)]
pub struct MockProvisioner {
    host: MockHost,
    ours: Arc<Mutex<Vec<String>>>,
    /// The devices handed out, so a test can drive packets through them.
    devices: MemoryTunFactory,
    /// Set to fail every call, to exercise the error path.
    failure: Option<String>,
}

impl Default for MockProvisioner {
    fn default() -> Self {
        Self::new(MockHost::new())
    }
}

impl MockProvisioner {
    /// A provisioner over a host.
    pub fn new(host: MockHost) -> Self {
        Self {
            host,
            ours: Arc::new(Mutex::new(Vec::new())),
            devices: MemoryTunFactory::new(),
            failure: None,
        }
    }

    /// A provisioner that refuses everything, with this reason.
    pub fn failing(reason: impl Into<String>) -> Self {
        Self {
            host: MockHost::new(),
            ours: Arc::new(Mutex::new(Vec::new())),
            devices: MemoryTunFactory::new(),
            failure: Some(reason.into()),
        }
    }

    /// The host it applies to.
    pub fn host(&self) -> &MockHost {
        &self.host
    }

    /// The device created for an interface name, if any.
    pub fn device(&self, name: &str) -> Option<Arc<MemoryTun>> {
        self.devices.device(name)
    }

    fn owned(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        match self.ours.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn apply(&self, plan: &InterfacePlan) -> Result<Changes, PluginError> {
        if let Some(reason) = &self.failure {
            return Err(PluginError::Unavailable(reason.clone()));
        }

        let ours = self.owned().iter().any(|name| name == &plan.name);
        let current = self
            .host
            .get(&plan.name)
            .unwrap_or_else(InterfaceState::absent);
        let changes = plan_changes(&current, plan, ours)?;

        let mut state = current;
        if changes.delete_link {
            self.host.lock().remove(&plan.name);
            state = InterfaceState::absent();
        }
        if changes.create_link {
            state = InterfaceState {
                kind: LinkKind::Tun,
                // Creating it means holding it open, so it has carrier.
                attached: true,
                up: false,
                mtu: 1500,
                addresses: Vec::new(),
            };
            self.owned().push(plan.name.clone());
        }
        if let Some(mtu) = changes.set_mtu {
            state.mtu = mtu;
        }
        if changes.bring_up {
            state.up = true;
        }
        state
            .addresses
            .retain(|addr| !changes.remove.contains(addr));
        state.addresses.extend(changes.add.iter().copied());
        state.addresses.sort();
        state.addresses.dedup();
        self.host.insert(plan.name.clone(), state);

        Ok(changes)
    }
}

impl InterfaceProvisioner for MockProvisioner {
    fn name(&self) -> &str {
        "mock"
    }

    fn reconcile<'a>(
        &'a self,
        plan: &'a InterfacePlan,
    ) -> BoxFuture<'a, Result<Provisioned, PluginError>> {
        Box::pin(async move {
            let changes = self.apply(plan)?;
            let device = if changes.create_link {
                Some(
                    self.devices
                        .create(TunRequest::bare(plan.name.clone(), plan.mtu))
                        .await?,
                )
            } else {
                None
            };
            Ok(Provisioned { changes, device })
        })
    }

    fn remove<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<(), PluginError>> {
        Box::pin(async move {
            self.host.lock().remove(name);
            self.owned().retain(|owned| owned != name);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v6() -> Cidr {
        Cidr {
            addr: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            prefix_len: 64,
        }
    }

    fn v4(last: u8) -> Cidr {
        Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 13, 37, last)),
            prefix_len: 24,
        }
    }

    fn plan(addresses: Vec<Cidr>) -> InterfacePlan {
        InterfacePlan::new("tsunmock", 1280, addresses)
    }

    #[tokio::test]
    async fn reconciling_an_empty_host_creates_a_configured_interface() {
        let provisioner = MockProvisioner::default();
        let plan = plan(vec![v6(), v4(69)]);
        let changes = provisioner.reconcile(&plan).await.unwrap().changes;
        assert!(changes.create_link);

        let state = provisioner.host().get("tsunmock").unwrap();
        assert_eq!(state.kind, LinkKind::Tun);
        assert!(state.up);
        assert_eq!(state.mtu, 1280);
        assert_eq!(state.addresses, vec![v4(69), v6()]);
    }

    #[tokio::test]
    async fn reconciling_is_idempotent() {
        let provisioner = MockProvisioner::default();
        let plan = plan(vec![v6(), v4(69)]);
        provisioner.reconcile(&plan).await.unwrap();
        let second = provisioner.reconcile(&plan).await.unwrap().changes;
        assert!(second.is_empty(), "{second:?}");
    }

    #[tokio::test]
    async fn a_crashed_run_is_repaired_on_the_next_start() {
        let host = MockHost::new();
        // What the previous run left: the interface, with the address it had
        // been allocated back then.
        host.insert_stale_tun("tsunmock", vec![v4(178)]);
        let provisioner = MockProvisioner::new(host);

        let changes = provisioner
            .reconcile(&plan(vec![v6(), v4(69)]))
            .await
            .unwrap()
            .changes;
        assert!(changes.delete_link && changes.create_link);

        let state = provisioner.host().get("tsunmock").unwrap();
        assert_eq!(
            state.addresses,
            vec![v4(69), v6()],
            "the stale address is gone and the current one is there"
        );
        assert!(state.attached, "the new interface is held open by us");
    }

    #[tokio::test]
    async fn a_changed_allocation_is_applied_without_recreating_the_interface() {
        let provisioner = MockProvisioner::default();
        provisioner
            .reconcile(&plan(vec![v6(), v4(69)]))
            .await
            .unwrap();

        // The overlay agreed on a different address for us while running.
        let changes = provisioner
            .reconcile(&plan(vec![v6(), v4(70)]))
            .await
            .unwrap()
            .changes;
        assert!(
            !changes.delete_link && !changes.create_link,
            "recreating would drop every tunnel"
        );
        assert_eq!(changes.add, vec![v4(70)]);
        assert_eq!(changes.remove, vec![v4(69)]);
        assert_eq!(
            provisioner.host().get("tsunmock").unwrap().addresses,
            vec![v4(70), v6()]
        );
    }

    #[tokio::test]
    async fn removing_takes_the_interface_off_the_host_and_is_idempotent() {
        let provisioner = MockProvisioner::default();
        provisioner.reconcile(&plan(vec![v6()])).await.unwrap();
        assert_eq!(provisioner.host().names(), vec!["tsunmock".to_string()]);

        provisioner.remove("tsunmock").await.unwrap();
        assert!(provisioner.host().names().is_empty());
        provisioner.remove("tsunmock").await.unwrap();
    }

    #[tokio::test]
    async fn a_foreign_interface_makes_reconciling_fail_and_changes_nothing() {
        let host = MockHost::new();
        host.insert(
            "tsunmock",
            InterfaceState {
                kind: LinkKind::Foreign("bridge".into()),
                attached: true,
                up: true,
                mtu: 1500,
                addresses: vec![v4(1)],
            },
        );
        let provisioner = MockProvisioner::new(host);
        assert!(provisioner.reconcile(&plan(vec![v6()])).await.is_err());

        let state = provisioner.host().get("tsunmock").unwrap();
        assert_eq!(state.kind, LinkKind::Foreign("bridge".into()));
        assert_eq!(state.addresses, vec![v4(1)], "left exactly as it was");
    }
}
