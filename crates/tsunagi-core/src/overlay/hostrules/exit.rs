//! Host rules for exit nodes: what the operating system needs for this agent
//! to carry other members' internet traffic, and for this device's own
//! traffic to go through a member.
//!
//! Two independent halves, planned together because one interface carries
//! both:
//!
//! * **Offering** — one set of rules per network that offers this agent as an
//!   exit node, chosen by that network's range: masquerade the range out of
//!   every other interface and let it through the forward chain. A network
//!   that does not offer has no rules, so its members' packets are dropped by
//!   the firewall as well as by the agent.
//! * **Using** — policy routing that sends everything the host does not have
//!   a more specific route for into the overlay interface, while the agent's
//!   own sockets keep the ordinary route (see `linux_exit`).
//!
//! Nothing a peer announces becomes a host setting. Offering is the owner's
//! switch; using is the user's choice of a member. Every object is tagged,
//! reversible, and removed when it is no longer wanted, when the network
//! leaves or stops, and when the agent stops.

use std::sync::{Arc, Mutex};

use crate::BoxFuture;
use crate::state::Ipv4Range;

use super::RuleOutcome;

/// What the host should hold for one interface's exit settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExitHostPlan {
    /// The overlay interface.
    pub interface: String,
    /// The ranges of every network that offers this agent as an exit node.
    pub offer: Vec<Ipv4Range>,
    /// Whether this device sends its internet traffic through a member.
    pub client: bool,
    /// The range of every network on the interface. Only the using side
    /// reads it, to keep this agent's own traffic *to* the overlay inside it
    /// where the host has no per-user routing (macOS).
    pub overlay: Vec<Ipv4Range>,
}

impl ExitHostPlan {
    /// Whether there is nothing to hold.
    pub fn is_empty(&self) -> bool {
        self.offer.is_empty() && !self.client
    }
}

/// What applying a plan achieved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExitHostReport {
    /// One outcome per offered range: its masquerade and forward rules.
    pub offer: Vec<(Ipv4Range, RuleOutcome)>,
    /// Whether the kernel forwards packets for the interface. `None` when it
    /// could not be read. The agent only reads this: turning forwarding on is
    /// the owner's decision.
    pub forwarding: Option<bool>,
    /// The routes and rules that send this device's traffic through the
    /// interface, when the plan asked for them.
    pub client: Option<RuleOutcome>,
}

/// Installs and removes exit-node rules for an overlay interface.
///
/// Like the broadcast rules, no call fails as a whole: a step that cannot be
/// done is in the report, because the caller's only useful response is to
/// say so.
pub trait ExitHostRules: Send + Sync + std::fmt::Debug + 'static {
    /// Makes the host match the plan, replacing what this agent put there
    /// for the interface before.
    fn apply<'a>(&'a self, plan: &'a ExitHostPlan) -> BoxFuture<'a, ExitHostReport>;

    /// Removes everything this agent put there for the interface. Succeeds
    /// when nothing is there: it runs on the shutdown path, and once at
    /// startup to take away what a crashed run left.
    fn clear<'a>(&'a self, interface: &'a str) -> BoxFuture<'a, ()>;
}

/// The tag every firewall object of one offered range carries.
pub fn exit_tag(interface: &str, range: &Ipv4Range) -> String {
    format!("{}{range}", exit_tag_prefix(interface))
}

/// The start of every tag for an interface; what cleanup selects by.
pub fn exit_tag_prefix(interface: &str) -> String {
    format!("tsunagi-exit:{interface}:")
}

/// The one-line detail for a set of offer outcomes.
pub fn offer_detail(outcome: &RuleOutcome, range: &Ipv4Range) -> String {
    match outcome {
        RuleOutcome::Applied => format!("masquerade + forward for {range} in place"),
        RuleOutcome::Failed(reason) => reason.clone(),
    }
}

/// An in-memory host for exit rules, for tests: nothing is touched.
#[derive(Debug, Clone, Default)]
pub struct MockExitRules {
    state: Arc<Mutex<Option<ExitHostPlan>>>,
    calls: Arc<Mutex<Vec<String>>>,
    forwarding: Arc<Mutex<Option<bool>>>,
    failure: Arc<Mutex<Option<String>>>,
}

impl MockExitRules {
    /// An empty host with forwarding turned on.
    pub fn new() -> Self {
        let rules = Self::default();
        *lock(&rules.forwarding) = Some(true);
        rules
    }

    /// What the host reports for kernel forwarding from now on.
    pub fn set_forwarding(&self, forwarding: Option<bool>) {
        *lock(&self.forwarding) = forwarding;
    }

    /// Makes every step fail with this reason from now on.
    pub fn fail_with(&self, reason: Option<String>) {
        *lock(&self.failure) = reason;
    }

    /// What is installed now.
    pub fn installed(&self) -> Option<ExitHostPlan> {
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

impl ExitHostRules for MockExitRules {
    fn apply<'a>(&'a self, plan: &'a ExitHostPlan) -> BoxFuture<'a, ExitHostReport> {
        Box::pin(async move {
            lock(&self.calls).push(format!("apply:{}", plan.interface));
            let outcome = match lock(&self.failure).clone() {
                Some(reason) => RuleOutcome::Failed(reason),
                None => {
                    *lock(&self.state) = Some(plan.clone());
                    RuleOutcome::Applied
                }
            };
            ExitHostReport {
                offer: plan
                    .offer
                    .iter()
                    .map(|range| (*range, outcome.clone()))
                    .collect(),
                forwarding: *lock(&self.forwarding),
                client: plan.client.then_some(outcome),
            }
        })
    }

    fn clear<'a>(&'a self, interface: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            lock(&self.calls).push(format!("clear:{interface}"));
            *lock(&self.state) = None;
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn range() -> Ipv4Range {
        "10.13.37.0/24".parse().unwrap()
    }

    #[test]
    fn tags_name_the_interface_and_the_range() {
        assert_eq!(
            exit_tag("tsun0", &range()),
            "tsunagi-exit:tsun0:10.13.37.0/24"
        );
        assert!(exit_tag("tsun0", &range()).starts_with(&exit_tag_prefix("tsun0")));
        // Another interface's tag never matches this one's prefix.
        assert!(!exit_tag("tsun01", &range()).starts_with(&exit_tag_prefix("tsun0")));
    }

    #[test]
    fn an_empty_plan_is_nothing_to_hold() {
        let mut plan = ExitHostPlan::default();
        assert!(plan.is_empty());
        plan.client = true;
        assert!(!plan.is_empty());
    }

    #[tokio::test]
    async fn the_mock_applies_reports_and_clears() {
        let rules = MockExitRules::new();
        let plan = ExitHostPlan {
            interface: "tsun0".into(),
            offer: vec![range()],
            client: true,
            overlay: vec![range()],
        };
        let report = rules.apply(&plan).await;
        assert_eq!(report.offer[0].1, RuleOutcome::Applied);
        assert_eq!(report.forwarding, Some(true));
        assert_eq!(report.client, Some(RuleOutcome::Applied));
        assert_eq!(rules.installed(), Some(plan));

        rules.set_forwarding(Some(false));
        rules.fail_with(Some("denied".into()));
        let report = rules
            .apply(&ExitHostPlan {
                interface: "tsun0".into(),
                offer: vec![range()],
                client: false,
                overlay: Vec::new(),
            })
            .await;
        assert_eq!(report.forwarding, Some(false));
        assert!(matches!(report.offer[0].1, RuleOutcome::Failed(_)));
        assert_eq!(report.client, None);

        rules.clear("tsun0").await;
        assert_eq!(rules.installed(), None);
        assert_eq!(rules.calls(), ["apply:tsun0", "apply:tsun0", "clear:tsun0"]);
    }
}
