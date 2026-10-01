//! Broadcast host rules on Linux: a netlink route and an `iptables` rule.
//!
//! The route is added by the netlink thread the interface provisioner already
//! owns (see [`super::super::provision`]), because that thread is the only one
//! that ever holds `CAP_NET_ADMIN`. It belongs to the interface and goes away
//! with it.
//!
//! The firewall allowance is a rule in the `INPUT` chain, inserted at the top
//! so a default-deny chain further down cannot drop discovery replies first:
//!
//! ```text
//! iptables -I INPUT 1 -i <if> -p udp -s <range> -m comment --comment tsunagi:<if> -j ACCEPT
//! ```
//!
//! `iptables` is a program, not a netlink call, so it is looked up in fixed
//! system directories rather than on `PATH`, and its arguments are built from
//! values this agent computed. It works with both the legacy backend and
//! `iptables-nft`. A host with only `nft` or `firewalld` has no `iptables`;
//! that is reported on the firewall half and the route is still installed.
//!
//! The rule carries a comment tag. That is how a rule left behind by a crashed
//! run is found and replaced, and why nothing else in the chain is ever
//! deleted.

use std::net::Ipv4Addr;

use crate::BoxFuture;
use crate::overlay::provision::RouteHandle;

use super::{BroadcastHostRules, BroadcastRulesPlan, BroadcastRulesReport, RuleOutcome, tag_for};

const CHAIN: &str = "INPUT";

/// Fixed places `iptables` is installed. Never `PATH`: the agent is
/// privileged and a directory a user controls must not decide what it runs.
const IPTABLES_DIRECTORIES: [&str; 5] = [
    "/usr/sbin/iptables",
    "/sbin/iptables",
    "/usr/bin/iptables",
    "/bin/iptables",
    "/usr/local/sbin/iptables",
];

/// The first candidate that exists.
fn pick_iptables(exists: impl Fn(&str) -> bool) -> Option<&'static str> {
    IPTABLES_DIRECTORIES
        .into_iter()
        .find(|candidate| exists(candidate))
}

/// What running `iptables` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ran {
    /// There is no `iptables` to run.
    Missing,
    /// It ran, and exited like this.
    Exited {
        success: bool,
        stdout: String,
        stderr: String,
    },
}

/// Runs `iptables` with these arguments. A function value so the flow below
/// can be tested without touching the host.
type Run<'a> = &'a dyn Fn(&[String]) -> Ran;

/// The match and target of the rule, without the chain or position.
fn rule_spec(plan: &BroadcastRulesPlan) -> Vec<String> {
    [
        "-i",
        plan.interface.as_str(),
        "-p",
        "udp",
        "-s",
        &plan.range.to_string(),
        "-m",
        "comment",
        "--comment",
        &plan.tag(),
        "-j",
        "ACCEPT",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Waits briefly for the xtables lock instead of failing when another tool
/// holds it.
fn locked(args: impl IntoIterator<Item = String>) -> Vec<String> {
    ["-w", "5"]
        .into_iter()
        .map(str::to_string)
        .chain(args)
        .collect()
}

fn check_args(plan: &BroadcastRulesPlan) -> Vec<String> {
    locked(
        ["-C".to_string(), CHAIN.to_string()]
            .into_iter()
            .chain(rule_spec(plan)),
    )
}

fn insert_args(plan: &BroadcastRulesPlan) -> Vec<String> {
    locked(
        ["-I".to_string(), CHAIN.to_string(), "1".to_string()]
            .into_iter()
            .chain(rule_spec(plan)),
    )
}

fn list_args() -> Vec<String> {
    locked(["-S".to_string(), CHAIN.to_string()])
}

/// Splits one `iptables -S` line into words, honouring double quotes, which
/// `iptables` puts around comments that need them.
fn split_rule_line(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            c if c.is_whitespace() && !quoted => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        words.push(current);
    }
    words
}

/// The delete commands for every rule in an `iptables -S INPUT` listing that
/// carries exactly this tag. Anything else in the chain is left alone.
fn tagged_deletions(listing: &str, tag: &str) -> Vec<Vec<String>> {
    listing
        .lines()
        .filter_map(|line| {
            let words = split_rule_line(line);
            let [append, chain, rest @ ..] = words.as_slice() else {
                return None;
            };
            if append != "-A" || chain != CHAIN {
                return None;
            }
            let tagged = rest
                .windows(2)
                .any(|pair| pair[0] == "--comment" && pair[1] == tag);
            tagged.then(|| {
                locked(
                    ["-D".to_string(), CHAIN.to_string()]
                        .into_iter()
                        .chain(rest.iter().cloned()),
                )
            })
        })
        .collect()
}

/// A failure message with the likely fix for the likely cause.
fn failure(stderr: &str) -> String {
    let text = stderr.trim();
    let lower = text.to_ascii_lowercase();
    if lower.contains("permission denied") || lower.contains("must be root") {
        format!("iptables needs root: {text}")
    } else if text.is_empty() {
        "iptables failed without saying why".to_string()
    } else {
        format!("iptables failed: {text}")
    }
}

fn missing(plan: &BroadcastRulesPlan) -> String {
    format!(
        "iptables not found; install it (the iptables-nft package is enough) or allow inbound \
         UDP from {} on `{}` in your firewall",
        plan.range, plan.interface
    )
}

/// Makes the firewall hold exactly one rule for this interface, the planned one.
fn apply_firewall(run: Run<'_>, plan: &BroadcastRulesPlan) -> RuleOutcome {
    let present = match run(&check_args(plan)) {
        Ran::Missing => return RuleOutcome::Failed(missing(plan)),
        Ran::Exited { success, .. } => success,
    };
    let listing = match run(&list_args()) {
        Ran::Missing => return RuleOutcome::Failed(missing(plan)),
        Ran::Exited {
            success: true,
            stdout,
            ..
        } => stdout,
        Ran::Exited { stderr, .. } => return RuleOutcome::Failed(failure(&stderr)),
    };
    let stale = tagged_deletions(&listing, &plan.tag());
    // `-C` matched an identical rule and nothing else carries our tag, so
    // there is nothing to do. Otherwise start from a clean slate for this
    // interface: a rule from an earlier run may name another range.
    if present && stale.len() == 1 {
        return RuleOutcome::Applied;
    }
    for delete in &stale {
        if let Ran::Exited {
            success: false,
            stderr,
            ..
        } = run(delete)
        {
            return RuleOutcome::Failed(failure(&stderr));
        }
    }
    match run(&insert_args(plan)) {
        Ran::Missing => RuleOutcome::Failed(missing(plan)),
        Ran::Exited { success: true, .. } => RuleOutcome::Applied,
        Ran::Exited { stderr, .. } => RuleOutcome::Failed(failure(&stderr)),
    }
}

/// Removes every rule tagged for this interface. Best effort.
fn clear_firewall(run: Run<'_>, interface: &str) {
    let Ran::Exited {
        success: true,
        stdout,
        ..
    } = run(&list_args())
    else {
        return;
    };
    for delete in tagged_deletions(&stdout, &tag_for(interface)) {
        if let Ran::Exited {
            success: false,
            stderr,
            ..
        } = run(&delete)
        {
            tracing::warn!(
                interface,
                "cannot remove the broadcast firewall rule: {}",
                failure(&stderr)
            );
        }
    }
}

/// Runs the real `iptables`.
fn run_iptables(args: &[String]) -> Ran {
    let Some(program) = pick_iptables(|path| std::path::Path::new(path).is_file()) else {
        return Ran::Missing;
    };
    match std::process::Command::new(program).args(args).output() {
        Ok(output) => Ran::Exited {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ran::Missing,
        Err(err) => Ran::Exited {
            success: false,
            stdout: String::new(),
            stderr: err.to_string(),
        },
    }
}

/// The Linux implementation: netlink for the route, `iptables` for the rule.
#[derive(Debug)]
pub struct LinuxHostRules {
    route: RouteHandle,
}

impl LinuxHostRules {
    pub(crate) fn new(route: RouteHandle) -> Self {
        Self { route }
    }

    async fn set_route(&self, interface: String, source: Ipv4Addr) -> RuleOutcome {
        let route = self.route.clone();
        match tokio::task::spawn_blocking(move || route.set(&interface, source)).await {
            Ok(Ok(())) => RuleOutcome::Applied,
            Ok(Err(err)) => RuleOutcome::Failed(err.to_string()),
            Err(err) => RuleOutcome::Failed(format!("the route task failed: {err}")),
        }
    }
}

impl BroadcastHostRules for LinuxHostRules {
    fn name(&self) -> &str {
        "netlink+iptables"
    }

    fn apply<'a>(&'a self, plan: &'a BroadcastRulesPlan) -> BoxFuture<'a, BroadcastRulesReport> {
        Box::pin(async move {
            let route = self.set_route(plan.interface.clone(), plan.source).await;
            let owned = plan.clone();
            let firewall =
                tokio::task::spawn_blocking(move || apply_firewall(&run_iptables, &owned))
                    .await
                    .unwrap_or_else(|err| {
                        RuleOutcome::Failed(format!("the firewall task failed: {err}"))
                    });
            BroadcastRulesReport {
                plan: plan.clone(),
                route,
                firewall,
            }
        })
    }

    fn clear<'a>(&'a self, interface: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let route = self.route.clone();
            let name = interface.to_string();
            let route_name = name.clone();
            if let Ok(Err(err)) =
                tokio::task::spawn_blocking(move || route.clear(&route_name)).await
            {
                tracing::warn!(interface = %name, %err, "cannot remove the broadcast route");
            }
            let name = interface.to_string();
            let _ = tokio::task::spawn_blocking(move || clear_firewall(&run_iptables, &name)).await;
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::cell::RefCell;

    fn plan() -> BroadcastRulesPlan {
        BroadcastRulesPlan {
            interface: "tsun0".into(),
            source: Ipv4Addr::new(10, 13, 37, 142),
            range: "10.13.37.0/24".parse().unwrap(),
        }
    }

    fn words(args: &[String]) -> String {
        args.join(" ")
    }

    #[test]
    fn the_rule_is_udp_only_from_the_overlay_range_on_this_interface() {
        let spec = words(&rule_spec(&plan()));
        assert_eq!(
            spec,
            "-i tsun0 -p udp -s 10.13.37.0/24 -m comment --comment tsunagi:tsun0 -j ACCEPT"
        );
        // Nothing here may widen to other protocols or every source.
        assert!(spec.contains("-p udp"));
        assert!(!spec.contains("0.0.0.0/0"));
        assert!(words(&insert_args(&plan())).starts_with("-w 5 -I INPUT 1 -i tsun0"));
        assert!(words(&check_args(&plan())).starts_with("-w 5 -C INPUT -i tsun0"));
    }

    #[test]
    fn iptables_is_found_in_fixed_directories_never_on_path() {
        assert_eq!(pick_iptables(|_| false), None);
        assert_eq!(
            pick_iptables(|p| p == "/sbin/iptables"),
            Some("/sbin/iptables")
        );
        assert_eq!(pick_iptables(|_| true), Some("/usr/sbin/iptables"));
    }

    #[test]
    fn only_rules_with_our_exact_tag_are_selected_for_deletion() {
        let listing = "\
-P INPUT DROP
-A INPUT -s 10.13.37.0/24 -i tsun0 -p udp -m comment --comment \"tsunagi:tsun0\" -j ACCEPT
-A INPUT -i tsun0 -m comment --comment tsunagi:tsun0 -j ACCEPT
-A INPUT -i tsun1 -p udp -m comment --comment tsunagi:tsun1 -j ACCEPT
-A INPUT -p tcp --dport 22 -m comment --comment \"allow ssh tsunagi:tsun0\" -j ACCEPT
-A FORWARD -i tsun0 -m comment --comment tsunagi:tsun0 -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
";
        let deletions = tagged_deletions(listing, "tsunagi:tsun0");
        assert_eq!(deletions.len(), 2, "{deletions:?}");
        assert_eq!(
            words(&deletions[0]),
            "-w 5 -D INPUT -s 10.13.37.0/24 -i tsun0 -p udp -m comment --comment tsunagi:tsun0 -j ACCEPT"
        );
        assert!(words(&deletions[1]).contains("-D INPUT -i tsun0 -m comment"));
        assert!(tagged_deletions("", "tsunagi:tsun0").is_empty());
    }

    /// A scripted `iptables`: answers by the leading verb, records every call.
    struct Fake {
        calls: RefCell<Vec<String>>,
        check_ok: bool,
        listing: String,
        insert_stderr: Option<&'static str>,
        missing: bool,
    }

    impl Fake {
        fn new(check_ok: bool, listing: &str) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                check_ok,
                listing: listing.to_string(),
                insert_stderr: None,
                missing: false,
            }
        }
        fn run(&self, args: &[String]) -> Ran {
            self.calls.borrow_mut().push(words(args));
            if self.missing {
                return Ran::Missing;
            }
            let ok = |stdout: &str| Ran::Exited {
                success: true,
                stdout: stdout.to_string(),
                stderr: String::new(),
            };
            match args.get(2).map(String::as_str) {
                Some("-C") if self.check_ok => ok(""),
                Some("-C") => Ran::Exited {
                    success: false,
                    stdout: String::new(),
                    stderr: "Bad rule".into(),
                },
                Some("-S") => ok(&self.listing),
                Some("-I") => match self.insert_stderr {
                    Some(stderr) => Ran::Exited {
                        success: false,
                        stdout: String::new(),
                        stderr: stderr.into(),
                    },
                    None => ok(""),
                },
                _ => ok(""),
            }
        }
        fn verbs(&self) -> Vec<String> {
            self.calls
                .borrow()
                .iter()
                .map(|call| call.split(' ').nth(2).unwrap().to_string())
                .collect()
        }
    }

    const ONE_OURS: &str =
        "-A INPUT -s 10.13.37.0/24 -i tsun0 -p udp -m comment --comment tsunagi:tsun0 -j ACCEPT\n";

    #[test]
    fn an_identical_rule_already_in_place_is_left_alone() {
        let fake = Fake::new(true, ONE_OURS);
        assert_eq!(
            apply_firewall(&|a| fake.run(a), &plan()),
            RuleOutcome::Applied
        );
        assert_eq!(fake.verbs(), ["-C", "-S"], "no insert, no delete");
    }

    #[test]
    fn a_missing_rule_is_inserted_once() {
        let fake = Fake::new(false, "-P INPUT ACCEPT\n");
        assert_eq!(
            apply_firewall(&|a| fake.run(a), &plan()),
            RuleOutcome::Applied
        );
        assert_eq!(fake.verbs(), ["-C", "-S", "-I"]);
    }

    #[test]
    fn a_stale_rule_for_another_range_is_replaced_not_stacked() {
        // A crashed run left a rule for an old range under our tag.
        let stale = "-A INPUT -s 10.99.0.0/16 -i tsun0 -p udp -m comment --comment tsunagi:tsun0 -j ACCEPT\n";
        let fake = Fake::new(false, stale);
        assert_eq!(
            apply_firewall(&|a| fake.run(a), &plan()),
            RuleOutcome::Applied
        );
        assert_eq!(fake.verbs(), ["-C", "-S", "-D", "-I"]);
    }

    #[test]
    fn duplicates_of_the_rule_collapse_to_one() {
        let doubled = format!("{ONE_OURS}{ONE_OURS}");
        let fake = Fake::new(true, &doubled);
        assert_eq!(
            apply_firewall(&|a| fake.run(a), &plan()),
            RuleOutcome::Applied
        );
        assert_eq!(fake.verbs(), ["-C", "-S", "-D", "-D", "-I"]);
    }

    #[test]
    fn a_missing_iptables_says_what_to_install_and_what_to_allow() {
        let mut fake = Fake::new(false, "");
        fake.missing = true;
        let RuleOutcome::Failed(reason) = apply_firewall(&|a| fake.run(a), &plan()) else {
            panic!("expected a failure");
        };
        assert!(reason.contains("iptables not found"), "{reason}");
        assert!(reason.contains("10.13.37.0/24"), "{reason}");
        assert!(reason.contains("tsun0"), "{reason}");
    }

    #[test]
    fn a_refused_insert_is_reported_with_the_cause() {
        let mut fake = Fake::new(false, "");
        fake.insert_stderr = Some(
            "iptables v1.8.10: can't initialize iptables table `filter': Permission denied (you must be root)",
        );
        let RuleOutcome::Failed(reason) = apply_firewall(&|a| fake.run(a), &plan()) else {
            panic!("expected a failure");
        };
        assert!(reason.starts_with("iptables needs root"), "{reason}");
    }

    #[test]
    fn clearing_removes_only_tagged_rules_and_ignores_a_missing_iptables() {
        let listing = format!(
            "-A INPUT -p tcp --dport 22 -j ACCEPT\n{ONE_OURS}-A INPUT -i tsun1 -m comment --comment tsunagi:tsun1 -j ACCEPT\n"
        );
        let fake = Fake::new(true, &listing);
        clear_firewall(&|a| fake.run(a), "tsun0");
        assert_eq!(fake.verbs(), ["-S", "-D"]);

        let mut gone = Fake::new(true, "");
        gone.missing = true;
        clear_firewall(&|a| gone.run(a), "tsun0");
        assert_eq!(gone.verbs(), ["-S"]);
    }

    #[test]
    fn rule_listing_words_honour_quotes() {
        assert_eq!(
            split_rule_line("-A INPUT -m comment --comment \"a b\" -j ACCEPT"),
            [
                "-A",
                "INPUT",
                "-m",
                "comment",
                "--comment",
                "a b",
                "-j",
                "ACCEPT"
            ]
        );
        assert!(split_rule_line("   ").is_empty());
    }
}
