//! Host rules that let a game's LAN discovery reach the overlay interface.
//!
//! Broadcast fanout happens at local TUN ingress (see [`super::broadcast`]),
//! so a limited broadcast only reaches Tsunagi if the operating system routes
//! it through the overlay interface, and a discovery *reply* only reaches the
//! game if the host firewall lets it in. Left to the user that is two manual
//! steps per host that nobody remembers, so when a network's broadcast is on
//! the agent installs exactly these two things for the interface it owns:
//!
//! * a `255.255.255.255/32` route through the overlay interface, with the
//!   overlay address as its preferred source, so the game's discovery packet
//!   leaves with a source address the router recognises;
//! * an inbound firewall allowance for **UDP only**, from the overlay range
//!   only, on that interface only. Replies to a broadcast come from a
//!   different address than the one the request was sent to, so a stateful
//!   firewall never matches them to the request. Opening every protocol
//!   would expose services such as SSH to every member of the network, which
//!   is not what a game needs.
//!
//! # Why this is allowed here
//!
//! The architecture says plugins never touch routing or firewall settings,
//! and nothing a peer announces becomes an OS setting. This is neither: it is
//! the system level, which owns the interface, configuring that interface from
//! values it computed itself (the interface name is derived locally, the
//! address and range come from signed state it already verified). Every object
//! is tagged `tsunagi:<interface>`, reversible, and removed when broadcast is
//! turned off, the network leaves, or the agent stops. A crash can leave a
//! firewall rule behind; the next apply for the same interface removes it.
//!
//! # Failure is contained
//!
//! Neither step can stop the agent. Each reports its own outcome, so a missing
//! firewall tool still leaves the route in place and says what is missing.
//!
//! # Why a trait
//!
//! Linux, Windows and the tests do this very differently, while *what* to
//! install is the same everywhere and lives in [`BroadcastRulesPlan`] and
//! [`rules_summary`], tested on every platform.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use crate::BoxFuture;
use crate::state::Ipv4Range;

mod exit;
pub use exit::{
    ExitHostPlan, ExitHostReport, ExitHostRules, MockExitRules, exit_tag, exit_tag_prefix,
    offer_detail,
};

#[cfg(all(feature = "tun-device", target_os = "linux"))]
mod linux;
#[cfg(all(feature = "tun-device", target_os = "linux"))]
mod linux_exit;
#[cfg(all(feature = "tun-device", target_os = "linux"))]
pub use linux::LinuxHostRules;

// Compiled everywhere so the scripts it builds are tested everywhere; only
// the type that runs them is exported on Windows.
mod windows;
#[cfg(all(feature = "tun-device", target_os = "windows"))]
pub use windows::WindowsHostRules;

#[cfg(all(feature = "tun-device", target_os = "macos"))]
mod macos;
#[cfg(all(feature = "tun-device", target_os = "macos"))]
pub use macos::MacosHostRules;

/// What the host should be told for one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastRulesPlan {
    /// The overlay interface. Derived locally from the network id, never from
    /// anything a peer said.
    pub interface: String,
    /// This agent's overlay address, the route's preferred source.
    pub source: Ipv4Addr,
    /// The overlay range inbound UDP is admitted from.
    pub range: Ipv4Range,
}

impl BroadcastRulesPlan {
    /// The tag every object carries, so it can be found again and nothing
    /// else is ever touched.
    pub fn tag(&self) -> String {
        tag_for(&self.interface)
    }
}

/// The tag for an interface's objects.
pub fn tag_for(interface: &str) -> String {
    format!("tsunagi:{interface}")
}

/// What happened to one of the two host objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOutcome {
    /// It is in place.
    Applied,
    /// It is not, with a reason a person can act on.
    Failed(String),
}

impl RuleOutcome {
    /// Whether the object is in place.
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied)
    }
}

/// What applying a plan achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastRulesReport {
    /// What was asked for.
    pub plan: BroadcastRulesPlan,
    /// The `255.255.255.255` route.
    pub route: RuleOutcome,
    /// The inbound firewall allowance.
    pub firewall: RuleOutcome,
}

impl BroadcastRulesReport {
    /// Whether both objects are in place.
    pub fn is_ok(&self) -> bool {
        self.route.is_applied() && self.firewall.is_applied()
    }

    /// One line for `status`.
    pub fn summary(&self) -> String {
        rules_summary(&self.route, &self.firewall)
    }
}

/// The status line for a pair of outcomes.
pub fn rules_summary(route: &RuleOutcome, firewall: &RuleOutcome) -> String {
    match (route, firewall) {
        (RuleOutcome::Applied, RuleOutcome::Applied) => "ok (route + firewall)".to_string(),
        (route, firewall) => {
            let part = |what: &str, outcome: &RuleOutcome| match outcome {
                RuleOutcome::Applied => format!("{what} ok"),
                RuleOutcome::Failed(reason) => format!("{what} failed: {reason}"),
            };
            format!(
                "incomplete; {}; {}",
                part("route", route),
                part("firewall", firewall)
            )
        }
    }
}

/// Installs and removes the host rules for an overlay interface.
///
/// Both calls are idempotent. Neither can fail as a whole: a step that cannot
/// be done is reported in the [`BroadcastRulesReport`], because the caller's
/// only useful response is to say so.
pub trait BroadcastHostRules: Send + Sync + std::fmt::Debug + 'static {
    /// A short name used in diagnostics.
    fn name(&self) -> &str;

    /// Makes the host match the plan, replacing whatever this agent put there
    /// for the same interface before.
    fn apply<'a>(&'a self, plan: &'a BroadcastRulesPlan) -> BoxFuture<'a, BroadcastRulesReport>;

    /// Removes what this agent put there for the interface. Succeeds when
    /// nothing is there: it runs on the shutdown path.
    fn clear<'a>(&'a self, interface: &'a str) -> BoxFuture<'a, ()>;

    /// The exit-node rules that go with these, when the platform has them.
    ///
    /// One object per host, because both halves need the same privileged
    /// helpers; the default is that this platform has none, which is said
    /// where it matters rather than pretended.
    fn exit_rules(&self) -> Option<&dyn ExitHostRules> {
        None
    }
}

/// The platform has no implementation, which is said rather than pretended.
#[derive(Debug, Default)]
pub struct UnsupportedHostRules;

impl BroadcastHostRules for UnsupportedHostRules {
    fn name(&self) -> &str {
        "unsupported"
    }

    fn apply<'a>(&'a self, plan: &'a BroadcastRulesPlan) -> BoxFuture<'a, BroadcastRulesReport> {
        Box::pin(async move {
            let reason = "host rules are not implemented on this platform; route \
                          255.255.255.255 through the overlay interface and allow inbound \
                          UDP from the overlay range yourself"
                .to_string();
            BroadcastRulesReport {
                plan: plan.clone(),
                route: RuleOutcome::Failed(reason.clone()),
                firewall: RuleOutcome::Failed(reason),
            }
        })
    }

    fn clear<'a>(&'a self, _interface: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {})
    }
}

/// What a [`MockHostRules`] currently holds, per interface.
pub type MockRulesState = std::collections::BTreeMap<String, BroadcastRulesPlan>;

/// An in-memory host, for tests: nothing is touched.
#[derive(Debug, Clone, Default)]
pub struct MockHostRules {
    exit: MockExitRules,
    state: Arc<Mutex<MockRulesState>>,
    calls: Arc<Mutex<Vec<String>>>,
    firewall_failure: Arc<Mutex<Option<String>>>,
}

impl MockHostRules {
    /// An empty host.
    pub fn new() -> Self {
        Self {
            exit: MockExitRules::new(),
            ..Self::default()
        }
    }

    /// The exit-node half of this host, for inspecting and steering tests.
    pub fn exit(&self) -> &MockExitRules {
        &self.exit
    }

    /// Makes the firewall step fail with this reason from now on.
    pub fn fail_firewall(&self, reason: impl Into<String>) {
        *lock(&self.firewall_failure) = Some(reason.into());
    }

    /// What is installed now.
    pub fn installed(&self) -> MockRulesState {
        lock(&self.state).clone()
    }

    /// Every `apply:<interface>` / `clear:<interface>` call, in order.
    pub fn calls(&self) -> Vec<String> {
        lock(&self.calls).clone()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl BroadcastHostRules for MockHostRules {
    fn name(&self) -> &str {
        "mock"
    }

    fn exit_rules(&self) -> Option<&dyn ExitHostRules> {
        Some(&self.exit)
    }

    fn apply<'a>(&'a self, plan: &'a BroadcastRulesPlan) -> BoxFuture<'a, BroadcastRulesReport> {
        Box::pin(async move {
            lock(&self.calls).push(format!("apply:{}", plan.interface));
            lock(&self.state).insert(plan.interface.clone(), plan.clone());
            let firewall = match lock(&self.firewall_failure).clone() {
                Some(reason) => RuleOutcome::Failed(reason),
                None => RuleOutcome::Applied,
            };
            BroadcastRulesReport {
                plan: plan.clone(),
                route: RuleOutcome::Applied,
                firewall,
            }
        })
    }

    fn clear<'a>(&'a self, interface: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            lock(&self.calls).push(format!("clear:{interface}"));
            lock(&self.state).remove(interface);
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn plan() -> BroadcastRulesPlan {
        BroadcastRulesPlan {
            interface: "tsun0".into(),
            source: Ipv4Addr::new(10, 13, 37, 142),
            range: "10.13.37.0/24".parse().unwrap(),
        }
    }

    #[test]
    fn every_object_is_tagged_with_its_interface() {
        assert_eq!(plan().tag(), "tsunagi:tsun0");
        assert_eq!(tag_for("tsun7"), "tsunagi:tsun7");
    }

    #[test]
    fn the_summary_says_which_half_is_missing() {
        assert_eq!(
            rules_summary(&RuleOutcome::Applied, &RuleOutcome::Applied),
            "ok (route + firewall)"
        );
        let line = rules_summary(
            &RuleOutcome::Applied,
            &RuleOutcome::Failed("iptables not found".into()),
        );
        assert!(line.contains("route ok"), "{line}");
        assert!(
            line.contains("firewall failed: iptables not found"),
            "{line}"
        );
        let report = BroadcastRulesReport {
            plan: plan(),
            route: RuleOutcome::Failed("denied".into()),
            firewall: RuleOutcome::Applied,
        };
        assert!(!report.is_ok());
        assert!(report.summary().contains("route failed: denied"));
    }

    #[tokio::test]
    async fn the_mock_applies_replaces_and_clears_idempotently() {
        let rules = MockHostRules::new();
        let first = rules.apply(&plan()).await;
        assert!(first.is_ok());
        assert_eq!(rules.installed().len(), 1);

        let mut moved = plan();
        moved.source = Ipv4Addr::new(10, 13, 37, 7);
        rules.apply(&moved).await;
        assert_eq!(rules.installed()["tsun0"].source, moved.source);

        rules.clear("tsun0").await;
        rules.clear("tsun0").await;
        assert!(rules.installed().is_empty());
        assert_eq!(rules.calls().len(), 4);
    }

    #[tokio::test]
    async fn an_unsupported_platform_reports_both_steps_failed() {
        let report = UnsupportedHostRules.apply(&plan()).await;
        assert!(!report.route.is_applied());
        assert!(!report.firewall.is_applied());
        UnsupportedHostRules.clear("tsun0").await;
    }
}
