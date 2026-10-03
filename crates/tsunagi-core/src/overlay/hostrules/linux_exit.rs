//! Exit-node host rules on Linux: `iptables` for the offering side, policy
//! routing over netlink for the using side.
//!
//! # Offering
//!
//! For every network that offers this agent as an exit node, three rules,
//! selected by that network's range and carrying the tag
//! `tsunagi-exit:<if>:<range>`:
//!
//! ```text
//! -t nat    POSTROUTING  -s <range> ! -o <if> -j MASQUERADE
//! -t filter FORWARD      -i <if> -s <range> ! -o <if> -j ACCEPT
//! -t filter FORWARD      -o <if> -d <range> -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
//! ```
//!
//! `! -o <if>` is the egress without naming it: whatever interface the
//! default route uses, now or after it changes. Kernel forwarding is only
//! *read*. Turning it on changes how the whole host behaves, which is the
//! owner's decision, so when it is off the rules are installed anyway and the
//! report says so.
//!
//! # Using
//!
//! Policy routing, with no `/1` routes and nothing in the main table:
//!
//! ```text
//! table 0x7473:  default dev <if>
//! 5280: from all uidrange <euid>-<euid> lookup main
//! 5290: from all lookup main suppress_prefixlength 0
//! 5300: from all lookup 0x7473
//! ```
//!
//! The first keeps the agent's *own* sockets off the tunnel: its QUIC, relay,
//! DHT and DNS traffic would otherwise be routed into the interface it is
//! carrying, a loop. The second lets every specific route — the LAN, another
//! VPN, a tunnel to somewhere else — keep working, because only the default
//! route is suppressed. The priorities sit after Tailscale's 5270.
//!
//! The first rule exempts a *user id*, so it is only right when the agent has
//! one of its own, as the packaged service does. An agent started from a login
//! session would take that user's own applications out of the tunnel with it,
//! and the exit node would silently do nothing for them. That is refused, not
//! guessed at: see [`client_refusal`].

use crate::BoxFuture;
use crate::state::Ipv4Range;

use super::RuleOutcome;
use super::exit::{ExitHostPlan, ExitHostReport, ExitHostRules, exit_tag, exit_tag_prefix};
use super::linux::{LinuxHostRules, Ran, Run, failure, locked, run_iptables, split_rule_line};

/// The chains the offering rules live in: `(table, chain)`.
const CHAINS: [(&str, &str); 2] = [("nat", "POSTROUTING"), ("filter", "FORWARD")];

/// One firewall rule: where it goes, and its match and target.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    table: &'static str,
    chain: &'static str,
    spec: Vec<String>,
}

fn owned(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| word.to_string()).collect()
}

/// The three rules of one offered range.
fn offer_rules(interface: &str, range: &Ipv4Range) -> Vec<Rule> {
    let range_text = range.to_string();
    let tag = exit_tag(interface, range);
    let comment = ["-m", "comment", "--comment", tag.as_str()];
    let spec = |head: &[&str], tail: &[&str]| -> Vec<String> {
        owned(head)
            .into_iter()
            .chain(owned(&comment))
            .chain(owned(tail))
            .collect()
    };
    vec![
        Rule {
            table: "nat",
            chain: "POSTROUTING",
            spec: spec(
                &["-s", &range_text, "!", "-o", interface],
                &["-j", "MASQUERADE"],
            ),
        },
        Rule {
            table: "filter",
            chain: "FORWARD",
            spec: spec(
                &["-i", interface, "-s", &range_text, "!", "-o", interface],
                &["-j", "ACCEPT"],
            ),
        },
        Rule {
            table: "filter",
            chain: "FORWARD",
            spec: spec(
                &[
                    "-o",
                    interface,
                    "-d",
                    &range_text,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "RELATED,ESTABLISHED",
                ],
                &["-j", "ACCEPT"],
            ),
        },
    ]
}

fn check_args(rule: &Rule) -> Vec<String> {
    locked(
        owned(&["-t", rule.table, "-C", rule.chain])
            .into_iter()
            .chain(rule.spec.iter().cloned()),
    )
}

fn insert_args(rule: &Rule) -> Vec<String> {
    locked(
        owned(&["-t", rule.table, "-I", rule.chain, "1"])
            .into_iter()
            .chain(rule.spec.iter().cloned()),
    )
}

fn list_args(table: &str, chain: &str) -> Vec<String> {
    locked(owned(&["-t", table, "-S", chain]))
}

/// A rule found in a listing whose comment starts with our prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Found {
    /// The whole tag.
    tag: String,
    /// The words after `-A <chain>`, which is what `-D` needs.
    rest: Vec<String>,
}

/// Every rule in an `iptables -S <chain>` listing carrying a tag that starts
/// with `prefix`. Anything else in the chain is left alone.
fn tagged_rules(listing: &str, chain: &str, prefix: &str) -> Vec<Found> {
    listing
        .lines()
        .filter_map(|line| {
            let words = split_rule_line(line);
            let [append, found_chain, rest @ ..] = words.as_slice() else {
                return None;
            };
            if append != "-A" || found_chain != chain {
                return None;
            }
            let tag = rest
                .windows(2)
                .find(|pair| pair[0] == "--comment" && pair[1].starts_with(prefix))
                .map(|pair| pair[1].clone())?;
            Some(Found {
                tag,
                rest: rest.to_vec(),
            })
        })
        .collect()
}

fn delete_args(table: &str, chain: &str, found: &Found) -> Vec<String> {
    locked(
        owned(&["-t", table, "-D", chain])
            .into_iter()
            .chain(found.rest.iter().cloned()),
    )
}

fn missing_iptables(range: &Ipv4Range, interface: &str) -> String {
    format!(
        "iptables not found; install it (the iptables-nft package is enough), or masquerade \
         {range} out of every interface but `{interface}` and forward it yourself"
    )
}

/// Reads one chain, or says why not.
fn read_chain(run: Run<'_>, table: &str, chain: &str) -> Result<String, Failure> {
    match run(&list_args(table, chain)) {
        Ran::Missing => Err(Failure::Missing),
        Ran::Exited {
            success: true,
            stdout,
            ..
        } => Ok(stdout),
        Ran::Exited { stderr, .. } => Err(Failure::Failed(failure(&stderr))),
    }
}

enum Failure {
    Missing,
    Failed(String),
}

/// Deletes found rules; the first failure ends it.
fn delete_all(
    run: Run<'_>,
    table: &str,
    chain: &str,
    found: &[Found],
    keep: impl Fn(&Found) -> bool,
) -> Result<(), String> {
    for rule in found.iter().filter(|rule| !keep(rule)) {
        if let Ran::Exited {
            success: false,
            stderr,
            ..
        } = run(&delete_args(table, chain, rule))
        {
            return Err(failure(&stderr));
        }
    }
    Ok(())
}

/// Makes the firewall hold exactly the offering rules of these ranges for the
/// interface, and no others of ours.
fn apply_offer(
    run: Run<'_>,
    interface: &str,
    ranges: &[Ipv4Range],
) -> Vec<(Ipv4Range, RuleOutcome)> {
    let fail_all = |reason: String| -> Vec<(Ipv4Range, RuleOutcome)> {
        ranges
            .iter()
            .map(|range| (*range, RuleOutcome::Failed(reason.clone())))
            .collect()
    };
    let prefix = exit_tag_prefix(interface);
    let wanted: Vec<String> = ranges.iter().map(|r| exit_tag(interface, r)).collect();

    // What is there now, per chain.
    let mut present: Vec<(&str, &str, Vec<Found>)> = Vec::new();
    for (table, chain) in CHAINS {
        match read_chain(run, table, chain) {
            Ok(listing) => present.push((table, chain, tagged_rules(&listing, chain, &prefix))),
            Err(Failure::Missing) => {
                return match ranges.first() {
                    Some(range) => fail_all(missing_iptables(range, interface)),
                    None => Vec::new(),
                };
            }
            Err(Failure::Failed(reason)) => return fail_all(reason),
        }
    }

    // Rules for a range no longer offered, or left by an earlier run.
    for (table, chain, found) in &present {
        if let Err(reason) = delete_all(run, table, chain, found, |rule| wanted.contains(&rule.tag))
        {
            return fail_all(reason);
        }
    }

    ranges
        .iter()
        .map(|range| {
            let rules = offer_rules(interface, range);
            let tag = exit_tag(interface, range);
            let in_place = rules
                .iter()
                .all(|rule| matches!(run(&check_args(rule)), Ran::Exited { success: true, .. }))
                && present.iter().all(|(_, chain, found)| {
                    let have = found.iter().filter(|rule| rule.tag == tag).count();
                    have == rules.iter().filter(|rule| rule.chain == *chain).count()
                });
            if in_place {
                return (*range, RuleOutcome::Applied);
            }
            // Start this range from a clean slate: a half-installed set, or
            // one that differs from the plan, is replaced as a whole.
            for (table, chain, found) in &present {
                if let Err(reason) = delete_all(run, table, chain, found, |rule| rule.tag != tag) {
                    return (*range, RuleOutcome::Failed(reason));
                }
            }
            for rule in &rules {
                match run(&insert_args(rule)) {
                    Ran::Missing => {
                        return (
                            *range,
                            RuleOutcome::Failed(missing_iptables(range, interface)),
                        );
                    }
                    Ran::Exited { success: true, .. } => {}
                    Ran::Exited { stderr, .. } => {
                        return (*range, RuleOutcome::Failed(failure(&stderr)));
                    }
                }
            }
            (*range, RuleOutcome::Applied)
        })
        .collect()
}

/// Removes every offering rule of ours for the interface. Best effort.
fn clear_offer(run: Run<'_>, interface: &str) {
    let prefix = exit_tag_prefix(interface);
    for (table, chain) in CHAINS {
        let Ok(listing) = read_chain(run, table, chain) else {
            continue;
        };
        let found = tagged_rules(&listing, chain, &prefix);
        if let Err(reason) = delete_all(run, table, chain, &found, |_| false) {
            tracing::warn!(
                interface,
                "cannot remove an exit node firewall rule: {reason}"
            );
        }
    }
}

/// The kernel's forwarding switch for packets arriving on the interface,
/// read from the text of the sysctl files. Never written.
fn forwarding_state(read: impl Fn(&str) -> Option<String>, interface: &str) -> Option<bool> {
    let flag = |text: String| match text.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    };
    // The name is derived here, but it ends up in a path.
    if !interface.is_empty() && !interface.contains(['/', '\0']) && interface != ".." {
        let per_interface = format!("/proc/sys/net/ipv4/conf/{interface}/forwarding");
        if let Some(state) = read(&per_interface).and_then(flag) {
            return Some(state);
        }
    }
    read("/proc/sys/net/ipv4/ip_forward").and_then(flag)
}

fn read_sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// The effective user id from the text of `/proc/self/status`.
fn parse_euid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|effective| effective.parse().ok())
}

/// Why the using side must not be installed for this process, if it must not.
///
/// The bypass rule exempts this process's *user id* from the tunnel. That is
/// right for a service with an id of its own and wrong for a process started
/// from somebody's login session, which shares its id with every application
/// that person runs. A login session is recognised by `XDG_RUNTIME_DIR`,
/// which `systemd --user` and the login managers set and a system service
/// does not. Crude on purpose: refusing a service that was started oddly is
/// a message, and exempting a user's applications is a silent failure.
fn client_refusal(xdg_runtime_dir: Option<&str>) -> Option<String> {
    xdg_runtime_dir.filter(|dir| !dir.is_empty()).map(|_| {
        "the exit node needs the agent to run as a system service with a user of its own: \
         this agent was started from a login session, so routing everything through the \
         overlay would take that user's own applications out of the tunnel with it"
            .to_string()
    })
}

impl LinuxHostRules {
    async fn blocking<T: Send + 'static>(
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, String> {
        tokio::task::spawn_blocking(work)
            .await
            .map_err(|err| format!("the task failed: {err}"))
    }

    async fn apply_client(&self, interface: &str) -> RuleOutcome {
        let xdg = std::env::var("XDG_RUNTIME_DIR").ok();
        if let Some(reason) = client_refusal(xdg.as_deref()) {
            // Whatever an earlier run left must not stay in force.
            self.clear_client().await;
            return RuleOutcome::Failed(reason);
        }
        let Some(euid) = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| parse_euid(&status))
        else {
            return RuleOutcome::Failed("cannot tell which user this agent runs as".to_string());
        };
        let route = self.route.clone();
        let interface = interface.to_string();
        match Self::blocking(move || route.set_exit_client(&interface, euid)).await {
            Ok(Ok(())) => RuleOutcome::Applied,
            Ok(Err(err)) => RuleOutcome::Failed(err.to_string()),
            Err(reason) => RuleOutcome::Failed(reason),
        }
    }

    async fn clear_client(&self) {
        let route = self.route.clone();
        if let Ok(Err(err)) = Self::blocking(move || route.clear_exit_client()).await {
            tracing::warn!(%err, "cannot remove the exit node routing rules");
        }
    }
}

impl ExitHostRules for LinuxHostRules {
    fn apply<'a>(&'a self, plan: &'a ExitHostPlan) -> BoxFuture<'a, ExitHostReport> {
        Box::pin(async move {
            let interface = plan.interface.clone();
            let ranges = plan.offer.clone();
            let offer = {
                let (job_interface, job_ranges) = (interface.clone(), ranges.clone());
                Self::blocking(move || apply_offer(&run_iptables, &job_interface, &job_ranges))
                    .await
                    .unwrap_or_else(|reason| {
                        ranges
                            .iter()
                            .map(|range| (*range, RuleOutcome::Failed(reason.clone())))
                            .collect()
                    })
            };
            let forwarding = if ranges.is_empty() {
                None
            } else {
                forwarding_state(read_sysctl, &interface)
            };
            let client = if plan.client {
                Some(self.apply_client(&interface).await)
            } else {
                self.clear_client().await;
                None
            };
            ExitHostReport {
                offer,
                forwarding,
                client,
            }
        })
    }

    fn clear<'a>(&'a self, interface: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let name = interface.to_string();
            let _ = Self::blocking(move || clear_offer(&run_iptables, &name)).await;
            self.clear_client().await;
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::cell::RefCell;

    use super::*;

    fn range() -> Ipv4Range {
        "10.13.37.0/24".parse().unwrap()
    }

    fn words(args: &[String]) -> String {
        args.join(" ")
    }

    #[test]
    fn the_rules_masquerade_the_range_out_of_every_other_interface_and_forward_it() {
        let rules = offer_rules("tsun0", &range());
        assert_eq!(rules.len(), 3);
        assert_eq!(
            words(&rules[0].spec),
            "-s 10.13.37.0/24 ! -o tsun0 -m comment --comment tsunagi-exit:tsun0:10.13.37.0/24 -j MASQUERADE"
        );
        assert_eq!((rules[0].table, rules[0].chain), ("nat", "POSTROUTING"));
        assert_eq!(
            words(&rules[1].spec),
            "-i tsun0 -s 10.13.37.0/24 ! -o tsun0 -m comment --comment tsunagi-exit:tsun0:10.13.37.0/24 -j ACCEPT"
        );
        assert_eq!((rules[1].table, rules[1].chain), ("filter", "FORWARD"));
        assert_eq!(
            words(&rules[2].spec),
            "-o tsun0 -d 10.13.37.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment tsunagi-exit:tsun0:10.13.37.0/24 -j ACCEPT"
        );
        // Nothing may widen to every source or to the other direction.
        for rule in &rules {
            assert!(!words(&rule.spec).contains("0.0.0.0/0"));
        }
        assert!(words(&insert_args(&rules[1])).starts_with("-w 5 -t filter -I FORWARD 1 -i tsun0"));
        assert!(words(&check_args(&rules[0])).starts_with("-w 5 -t nat -C POSTROUTING -s"));
    }

    #[test]
    fn only_rules_with_our_tag_for_this_interface_are_selected() {
        let listing = "\
-P FORWARD DROP
-A FORWARD -i tsun0 -s 10.13.37.0/24 ! -o tsun0 -m comment --comment tsunagi-exit:tsun0:10.13.37.0/24 -j ACCEPT
-A FORWARD -i tsun1 -m comment --comment tsunagi-exit:tsun1:10.99.0.0/24 -j ACCEPT
-A FORWARD -i tsun01 -m comment --comment tsunagi-exit:tsun01:10.5.0.0/24 -j ACCEPT
-A FORWARD -m comment --comment \"allow tsunagi-exit:tsun0:x\" -j ACCEPT
-A FORWARD -m comment --comment tsunagi:tsun0 -j ACCEPT
-A INPUT -m comment --comment tsunagi-exit:tsun0:10.13.37.0/24 -j ACCEPT
-A FORWARD -j ACCEPT
";
        let found = tagged_rules(listing, "FORWARD", &exit_tag_prefix("tsun0"));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].tag, "tsunagi-exit:tsun0:10.13.37.0/24");
        assert_eq!(
            words(&delete_args("filter", "FORWARD", &found[0])),
            "-w 5 -t filter -D FORWARD -i tsun0 -s 10.13.37.0/24 ! -o tsun0 -m comment --comment tsunagi-exit:tsun0:10.13.37.0/24 -j ACCEPT"
        );
        assert!(tagged_rules("", "FORWARD", "tsunagi-exit:tsun0:").is_empty());
    }

    /// A scripted `iptables` that remembers which rules it was given.
    struct Fake {
        calls: RefCell<Vec<String>>,
        /// Rules present, as `-S` lines per `(table, chain)`.
        listing: RefCell<Vec<(String, String)>>,
        missing: bool,
        check_ok: bool,
    }

    impl Fake {
        fn new(check_ok: bool) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                listing: RefCell::new(Vec::new()),
                missing: false,
                check_ok,
            }
        }

        fn with_rule(self, table: &str, line: &str) -> Self {
            self.listing
                .borrow_mut()
                .push((table.to_string(), line.to_string()));
            self
        }

        fn run(&self, args: &[String]) -> Ran {
            if self.missing {
                return Ran::Missing;
            }
            let line = args.join(" ");
            self.calls.borrow_mut().push(line.clone());
            let table = args
                .iter()
                .position(|word| word == "-t")
                .map(|at| args[at + 1].clone())
                .unwrap_or_default();
            let ok = |stdout: String| Ran::Exited {
                success: true,
                stdout,
                stderr: String::new(),
            };
            if line.contains(" -S ") {
                let listing: Vec<String> = self
                    .listing
                    .borrow()
                    .iter()
                    .filter(|(t, _)| *t == table)
                    .map(|(_, l)| l.clone())
                    .collect();
                return ok(listing.join("\n"));
            }
            if line.contains(" -C ") {
                return Ran::Exited {
                    success: self.check_ok,
                    stdout: String::new(),
                    stderr: String::new(),
                };
            }
            ok(String::new())
        }

        fn verbs(&self, verb: &str) -> Vec<String> {
            self.calls
                .borrow()
                .iter()
                .filter(|call| call.contains(&format!(" {verb} ")))
                .cloned()
                .collect()
        }
    }

    #[test]
    fn a_fresh_host_gets_the_three_rules() {
        let fake = Fake::new(false);
        let outcome = apply_offer(&|args| fake.run(args), "tsun0", &[range()]);
        assert_eq!(outcome, vec![(range(), RuleOutcome::Applied)]);
        let inserted = fake.verbs("-I");
        assert_eq!(inserted.len(), 3, "{inserted:?}");
        assert!(inserted[0].contains("-t nat -I POSTROUTING 1"));
        assert!(fake.verbs("-D").is_empty());
    }

    #[test]
    fn rules_already_in_place_are_left_alone() {
        let tag = exit_tag("tsun0", &range());
        let fake = Fake::new(true)
            .with_rule(
                "nat",
                &format!("-A POSTROUTING -s 10.13.37.0/24 ! -o tsun0 -m comment --comment {tag} -j MASQUERADE"),
            )
            .with_rule("filter", &format!("-A FORWARD -i tsun0 -m comment --comment {tag} -j ACCEPT"))
            .with_rule("filter", &format!("-A FORWARD -o tsun0 -m comment --comment {tag} -j ACCEPT"));
        let outcome = apply_offer(&|args| fake.run(args), "tsun0", &[range()]);
        assert_eq!(outcome, vec![(range(), RuleOutcome::Applied)]);
        assert!(fake.verbs("-I").is_empty());
        assert!(fake.verbs("-D").is_empty());
    }

    #[test]
    fn a_stale_range_is_removed_and_a_half_installed_set_is_replaced() {
        let old: Ipv4Range = "10.99.0.0/24".parse().unwrap();
        let old_tag = exit_tag("tsun0", &old);
        let tag = exit_tag("tsun0", &range());
        let fake = Fake::new(true)
            .with_rule(
                "nat",
                &format!(
                    "-A POSTROUTING -s 10.99.0.0/24 -m comment --comment {old_tag} -j MASQUERADE"
                ),
            )
            // Only one of the three for the current range.
            .with_rule(
                "filter",
                &format!("-A FORWARD -i tsun0 -m comment --comment {tag} -j ACCEPT"),
            )
            // Somebody else's rule, which must survive.
            .with_rule("filter", "-A FORWARD -i eth0 -j ACCEPT");
        let outcome = apply_offer(&|args| fake.run(args), "tsun0", &[range()]);
        assert_eq!(outcome, vec![(range(), RuleOutcome::Applied)]);
        let deleted = fake.verbs("-D");
        assert!(
            deleted.iter().any(|call| call.contains(&old_tag)),
            "{deleted:?}"
        );
        assert!(
            deleted.iter().any(|call| call.contains(&tag)),
            "{deleted:?}"
        );
        assert!(
            deleted.iter().all(|call| !call.contains("eth0")),
            "{deleted:?}"
        );
        assert_eq!(fake.verbs("-I").len(), 3);
    }

    #[test]
    fn clearing_removes_only_our_rules_for_the_interface() {
        let tag = exit_tag("tsun0", &range());
        let other = exit_tag("tsun1", &range());
        let fake = Fake::new(true)
            .with_rule(
                "nat",
                &format!("-A POSTROUTING -m comment --comment {tag} -j MASQUERADE"),
            )
            .with_rule(
                "nat",
                &format!("-A POSTROUTING -m comment --comment {other} -j MASQUERADE"),
            )
            .with_rule("filter", "-A FORWARD -j ACCEPT");
        clear_offer(&|args| fake.run(args), "tsun0");
        let deleted = fake.verbs("-D");
        assert_eq!(deleted.len(), 1, "{deleted:?}");
        assert!(deleted[0].contains(&tag));
    }

    #[test]
    fn a_missing_iptables_is_a_failure_that_says_what_to_do() {
        let mut fake = Fake::new(false);
        fake.missing = true;
        let outcome = apply_offer(&|args| fake.run(args), "tsun0", &[range()]);
        let RuleOutcome::Failed(reason) = &outcome[0].1 else {
            panic!("{outcome:?}");
        };
        assert!(reason.contains("iptables not found"), "{reason}");
        assert!(reason.contains("10.13.37.0/24"), "{reason}");
        // Nothing wanted and nothing to run is not a failure of anything.
        assert!(apply_offer(&|args| fake.run(args), "tsun0", &[]).is_empty());
    }

    #[test]
    fn forwarding_is_read_per_interface_then_globally_and_never_written() {
        let files = |per: Option<&'static str>, global: Option<&'static str>| {
            move |path: &str| match path {
                "/proc/sys/net/ipv4/conf/tsun0/forwarding" => per.map(str::to_string),
                "/proc/sys/net/ipv4/ip_forward" => global.map(str::to_string),
                _ => None,
            }
        };
        assert_eq!(
            forwarding_state(files(Some("1\n"), Some("0\n")), "tsun0"),
            Some(true)
        );
        assert_eq!(
            forwarding_state(files(Some("0\n"), Some("1\n")), "tsun0"),
            Some(false)
        );
        assert_eq!(
            forwarding_state(files(None, Some("1\n")), "tsun0"),
            Some(true)
        );
        assert_eq!(forwarding_state(files(None, None), "tsun0"), None);
        assert_eq!(forwarding_state(files(Some("junk"), None), "tsun0"), None);
        // A name that would leave the directory is not looked up.
        assert_eq!(forwarding_state(files(Some("1"), None), "../../x"), None);
    }

    #[test]
    fn the_effective_uid_is_the_second_field() {
        let status = "Name:\ttsunagi\nUid:\t1001\t1002\t1001\t1001\nGid:\t5\t5\t5\t5\n";
        assert_eq!(parse_euid(status), Some(1002));
        assert_eq!(parse_euid("Name:\tx\n"), None);
    }

    #[test]
    fn a_login_session_is_refused_and_a_service_is_not() {
        let reason = client_refusal(Some("/run/user/1000")).unwrap();
        assert!(reason.contains("system service"), "{reason}");
        assert!(client_refusal(None).is_none());
        assert!(client_refusal(Some("")).is_none());
    }
}
