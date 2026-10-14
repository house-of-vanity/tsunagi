//! Own-bit connection marks for exit-client underlay traffic.
//! Reply marks are restored before host reverse-path filtering, never accepted
//! around it. No peer address becomes a host route or firewall argument.

use super::linux::{Ran, failure, locked, split_rule_line};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Outside Tailscale's 0xff0000 mask and ordinary low-bit WireGuard marks.
pub(crate) const UNDERLAY_MARK: u32 = 0x4000_0000;
pub(crate) const UNDERLAY_MASK: u32 = UNDERLAY_MARK;
const MARK: &str = "0x40000000/0x40000000";
const MASK: &str = "0x40000000";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Listener {
    address: IpAddr,
    port: u16,
    tcp: bool,
}

fn parse_listeners(listing: &str, uid: u32, v6: bool, tcp: bool) -> Result<Vec<Listener>, String> {
    let mut result = Vec::new();
    for line in listing.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if (tcp && fields.get(3) != Some(&"0A"))
            || fields.get(7).and_then(|s| s.parse::<u32>().ok()) != Some(uid)
        {
            continue;
        }
        let (address, port) = fields
            .get(1)
            .and_then(|s| s.split_once(':'))
            .ok_or("malformed local socket")?;
        let port = u16::from_str_radix(port, 16).map_err(|e| e.to_string())?;
        let address = if v6 {
            let mut bytes = [0; 16];
            for (word, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                let hex = address
                    .get(word * 8..word * 8 + 8)
                    .ok_or("malformed local IPv6 listener")?;
                chunk.copy_from_slice(
                    &u32::from_str_radix(hex, 16)
                        .map_err(|e| e.to_string())?
                        .to_ne_bytes(),
                );
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        } else {
            IpAddr::V4(Ipv4Addr::from(
                u32::from_str_radix(address, 16)
                    .map_err(|e| e.to_string())?
                    .to_ne_bytes(),
            ))
        };
        if result.len() == 128 {
            return Err("too many local sockets for exit protection".into());
        }
        if port != 0 {
            result.push(Listener { address, port, tcp });
        }
    }
    Ok(result)
}

pub(super) fn local_sockets(uid: u32, v6: bool) -> Result<Vec<Listener>, String> {
    let mut listeners = Vec::new();
    for (protocol, tcp) in [("tcp", true), ("udp", false)] {
        for family in [false, true].into_iter().filter(|f| !f || v6) {
            let path = format!("/proc/net/{protocol}{}", if family { "6" } else { "" });
            listeners.extend(parse_listeners(
                &std::fs::read_to_string(path).map_err(|e| e.to_string())?,
                uid,
                family,
                tcp,
            )?);
        }
    }
    listeners.sort();
    listeners.dedup();
    Ok(listeners)
}

fn listener_rules(interface: &str, listener: &Listener) -> Vec<Vec<String>> {
    let mut base = words(&[
        "!",
        "-i",
        interface,
        "-p",
        if listener.tcp { "tcp" } else { "udp" },
        "--dport",
        &listener.port.to_string(),
    ]);
    if !listener.address.is_unspecified() {
        base.extend(words(&["-d", &listener.address.to_string()]));
    }
    // Match an actual local socket, not just a destination port. Listening
    // sockets need protection on the first packet, before any outbound connmark.
    base.extend(words(&[
        "-m",
        "socket",
        "--nowildcard",
        "-m",
        "comment",
        "--comment",
        &listener_tag(interface),
    ]));
    let save = base
        .iter()
        .cloned()
        .chain(words(&[
            "-m",
            "mark",
            "--mark",
            MARK,
            "-j",
            "CONNMARK",
            "--save-mark",
            "--nfmask",
            MASK,
            "--ctmask",
            MASK,
        ]))
        .collect();
    let mark = base
        .into_iter()
        .chain(words(&["-j", "MARK", "--set-xmark", MARK]))
        .collect();
    vec![save, mark]
}
pub(super) type RunFamily<'a> = &'a dyn Fn(bool, &[String]) -> Ran;

fn tag(interface: &str) -> String {
    format!("tsunagi-exit-underlay:{interface}")
}

fn listener_tag(interface: &str) -> String {
    format!("tsunagi-exit-sockets:{interface}")
}

fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}

fn rules(interface: &str, uid: u32) -> Vec<(&'static str, Vec<String>)> {
    let tag = tag(interface);
    let uid = uid.to_string();
    // Insert at position one in this order: final OUTPUT order is MARK, SAVE.
    vec![
        (
            "PREROUTING",
            words(&[
                "!",
                "-i",
                interface,
                "-m",
                "connmark",
                "--mark",
                MARK,
                "-m",
                "comment",
                "--comment",
                &tag,
                "-j",
                "CONNMARK",
                "--restore-mark",
                "--nfmask",
                MASK,
                "--ctmask",
                MASK,
            ]),
        ),
        (
            "OUTPUT",
            words(&[
                "-m",
                "owner",
                "--uid-owner",
                &uid,
                "-m",
                "mark",
                "--mark",
                MARK,
                "-m",
                "comment",
                "--comment",
                &tag,
                "-j",
                "CONNMARK",
                "--save-mark",
                "--nfmask",
                MASK,
                "--ctmask",
                MASK,
            ]),
        ),
        (
            "OUTPUT",
            words(&[
                "-m",
                "owner",
                "--uid-owner",
                &uid,
                "-m",
                "comment",
                "--comment",
                &tag,
                "-j",
                "MARK",
                "--set-xmark",
                MARK,
            ]),
        ),
    ]
}

fn execute(run: RunFamily<'_>, v6: bool, args: Vec<String>) -> Result<String, String> {
    match run(v6, &locked(args)) {
        Ran::Exited {
            success: true,
            stdout,
            ..
        } => Ok(stdout),
        Ran::Exited { stderr, .. } => Err(failure(&stderr)),
        Ran::Missing => Err(format!(
            "{} is required for exit-node connection marks",
            if v6 { "ip6tables" } else { "iptables" }
        )),
    }
}

/// Removes only exact interface tags, retaining other agents and host rules.
pub(super) fn clear(run: RunFamily<'_>, interface: &str, v6: bool) -> Result<(), String> {
    clear_tags(run, interface, v6, false)
}

fn clear_tags(
    run: RunFamily<'_>,
    interface: &str,
    v6: bool,
    sockets_only: bool,
) -> Result<(), String> {
    let wanted = tag(interface);
    let sockets = listener_tag(interface);
    for family in [false, true].into_iter().filter(|family| !family || v6) {
        let chains: &[&str] = if sockets_only {
            &["PREROUTING"]
        } else {
            &["OUTPUT", "PREROUTING"]
        };
        for chain in chains {
            let listing = execute(run, family, words(&["-t", "mangle", "-S", chain]))?;
            for line in listing.lines() {
                let tokens = split_rule_line(line);
                let [append, listed_chain, rest @ ..] = tokens.as_slice() else {
                    continue;
                };
                if append == "-A"
                    && listed_chain == *chain
                    && rest.windows(2).any(|pair| {
                        pair[0] == "--comment"
                            && (pair[1] == sockets || (!sockets_only && pair[1] == wanted))
                    })
                {
                    let args = words(&["-t", "mangle", "-D", chain])
                        .into_iter()
                        .chain(rest.iter().cloned())
                        .collect();
                    execute(run, family, args)?;
                }
            }
        }
    }
    Ok(())
}

/// Establishes protection before routing may redirect application traffic.
pub(super) fn install(
    run: RunFamily<'_>,
    interface: &str,
    uid: u32,
    v6: bool,
) -> Result<Vec<Listener>, String> {
    let listeners = local_sockets(uid, v6)?;
    install_with_listeners(run, interface, uid, v6, &listeners)?;
    Ok(listeners)
}

fn install_with_listeners(
    run: RunFamily<'_>,
    interface: &str,
    uid: u32,
    v6: bool,
    listeners: &[Listener],
) -> Result<(), String> {
    clear(run, interface, v6)?;
    let result = (|| {
        for family in [false, true].into_iter().filter(|family| !family || v6) {
            for (chain, spec) in rules(interface, uid) {
                let args = words(&["-t", "mangle", "-I", chain, "1"])
                    .into_iter()
                    .chain(spec)
                    .collect();
                execute(run, family, args)?;
            }
            for listener in listeners.iter().filter(|s| s.address.is_ipv6() == family) {
                for spec in listener_rules(interface, listener) {
                    execute(
                        run,
                        family,
                        words(&["-t", "mangle", "-I", "PREROUTING", "1"])
                            .into_iter()
                            .chain(spec)
                            .collect(),
                    )?;
                }
            }
        }
        Ok(())
    })();
    if result.is_err()
        && let Err(cleanup) = clear(run, interface, v6)
    {
        return Err(format!(
            "{}; cannot roll back connection marks: {cleanup}",
            result.err().unwrap_or_default()
        ));
    }
    result
}

/// Updates passive protection without interrupting established connmark rules.
pub(super) fn refresh(
    run: RunFamily<'_>,
    interface: &str,
    v6: bool,
    listeners: &[Listener],
) -> Result<(), String> {
    clear_tags(run, interface, v6, true)?;
    for family in [false, true].into_iter().filter(|f| !f || v6) {
        for listener in listeners.iter().filter(|s| s.address.is_ipv6() == family) {
            for spec in listener_rules(interface, listener) {
                execute(
                    run,
                    family,
                    words(&["-t", "mangle", "-I", "PREROUTING", "1"])
                        .into_iter()
                        .chain(spec)
                        .collect(),
                )?;
            }
        }
    }
    Ok(())
}

/// Kernel strict RPF must include the restored mark, independently of iptables.
pub(super) fn check_kernel_rpf(
    all_rpf: u32,
    all_valid: u32,
    interfaces: &[(String, u32, u32)],
) -> Result<(), String> {
    for (interface, rpf, valid) in interfaces {
        if all_rpf.max(*rpf) == 1 && all_valid.max(*valid) == 0 {
            return Err(format!(
                "strict rp_filter on `{interface}` ignores connection marks; enable net.ipv4.conf.all.src_valid_mark=1 before using an exit node (rp_filter stays enabled)"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn both_families_restore_before_firewall_and_preserve_foreign_mark_bits() {
        let calls = RefCell::new(Vec::new());
        let run = |v6, args: &[String]| {
            calls.borrow_mut().push((v6, args.to_vec()));
            Ran::Exited {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }
        };
        install_with_listeners(&run, "tsun0", 990, true, &[]).unwrap();
        let calls = calls.borrow();
        for family in [false, true] {
            let inserts: Vec<_> = calls
                .iter()
                .filter(|(v6, a)| *v6 == family && a.iter().any(|s| s == "-I"))
                .map(|(_, a)| a.join(" "))
                .collect();
            assert_eq!(inserts.len(), 3);
            assert!(inserts[0].contains("-I PREROUTING 1 ! -i tsun0 -m connmark"));
            assert!(inserts[0].contains("--restore-mark --nfmask 0x40000000 --ctmask 0x40000000"));
            assert!(inserts[1].contains("--uid-owner 990"));
            assert!(inserts[1].contains("--save-mark"));
            assert!(inserts[2].contains("--set-xmark 0x40000000/0x40000000"));
            assert!(
                !inserts
                    .iter()
                    .any(|s| s.contains("-j ACCEPT") || s.contains("-j RETURN"))
            );
        }
        assert_eq!(UNDERLAY_MASK & 0x00ff_0000, 0);
    }

    #[test]
    fn cleanup_retains_other_interfaces_and_rolls_back_partial_ipv6_installation() {
        let calls = RefCell::new(Vec::new());
        let run = |v6, args: &[String]| {
            calls.borrow_mut().push((v6, args.to_vec()));
            let listing = "-A OUTPUT -m comment --comment tsunagi-exit-underlay:tsun0 -j MARK --set-xmark 0x40000000/0x40000000\n-A OUTPUT -m comment --comment tsunagi-exit-underlay:tsun1 -j MARK --set-xmark 0x40000000/0x40000000\n-A OUTPUT -m comment --comment unrelated -j RETURN\n";
            Ran::Exited {
                success: !(v6 && args.iter().any(|s| s == "-I")),
                stdout: if args.iter().any(|s| s == "-S") {
                    listing.into()
                } else {
                    String::new()
                },
                stderr: "injected IPv6 failure".into(),
            }
        };
        assert!(install_with_listeners(&run, "tsun0", 990, true, &[]).is_err());
        let calls = calls.borrow();
        let deletions: Vec<_> = calls
            .iter()
            .filter(|(_, a)| a.iter().any(|s| s == "-D"))
            .collect();
        assert!(
            deletions.len() >= 4,
            "both initial and rollback cleanup run"
        );
        assert!(
            deletions
                .iter()
                .all(|(_, a)| a.iter().any(|s| s == "tsunagi-exit-underlay:tsun0"))
        );
    }

    #[test]
    fn kernel_strict_validation_requires_mark_awareness_without_weakening_rpf() {
        let interfaces = vec![("eth0".into(), 1, 0)];
        assert!(check_kernel_rpf(0, 0, &interfaces).is_err());
        assert!(check_kernel_rpf(0, 1, &interfaces).is_ok());
        assert!(check_kernel_rpf(2, 0, &interfaces).is_ok());
        assert!(check_kernel_rpf(0, 0, &[("eth0".into(), 1, 1)]).is_ok());
    }

    #[test]
    fn passive_tcp_protection_uses_only_locally_owned_listeners() {
        let listing = "header\n0: 00000000:01BB 00000000:0000 0A 0:0 0:0 0 990 0 1\n1: 0100007F:1111 00000000:0000 0A 0:0 0:0 0 1000 0 2\n2: 0100007F:2222 00000000:0000 01 0:0 0:0 0 990 0 3\n";
        let listeners = parse_listeners(listing, 990, false, true).unwrap();
        assert_eq!(
            listeners,
            vec![Listener {
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 443,
                tcp: true
            }]
        );
        let rules = listener_rules("tsun0", &listeners[0]);
        assert!(
            rules[0]
                .join(" ")
                .contains("-p tcp --dport 443 -m socket --nowildcard")
        );
        assert!(rules[0].join(" ").contains("--save-mark"));
        assert!(rules[1].join(" ").contains("--set-xmark"));
    }

    #[test]
    fn listener_parser_checks_family_encoding_and_bounds() {
        let loopback = Ipv6Addr::LOCALHOST.octets();
        let hex: String = loopback
            .as_chunks::<4>()
            .0
            .iter()
            .map(|bytes| format!("{:08X}", u32::from_ne_bytes(*bytes)))
            .collect();
        let listing = format!("header\n0: {hex}:01BB 0:0 0A 0:0 0:0 0 990 0 1\n");
        assert_eq!(
            parse_listeners(&listing, 990, true, true).unwrap(),
            vec![Listener {
                address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                port: 443,
                tcp: true
            }]
        );
        assert!(
            parse_listeners(
                "header\n0: BAD:01BB 0:0 0A 0:0 0:0 0 990 0 1",
                990,
                true,
                true
            )
            .is_err()
        );
        let huge = format!(
            "header\n{}",
            "0: 00000000:01BB 0:0 0A 0:0 0:0 0 990 0 1\n".repeat(129)
        );
        assert!(parse_listeners(&huge, 990, false, true).is_err());
    }

    #[test]
    fn udp_refresh_preserves_general_connmark_protection_and_other_interfaces() {
        let listing = "header\n0: 00000000:ABA0 0:0 07 0:0 0:0 0 990 0 1\n1: 00000000:0000 0:0 07 0:0 0:0 0 990 0 2\n";
        let sockets = parse_listeners(listing, 990, false, false).unwrap();
        assert_eq!(sockets.len(), 1);
        assert!(!sockets[0].tcp);
        let calls = RefCell::new(Vec::new());
        let run = |v6, args: &[String]| {
            calls.borrow_mut().push((v6, args.join(" ")));
            Ran::Exited { success: true, stdout: "-A PREROUTING -m comment --comment tsunagi-exit-underlay:tsun0 -j CONNMARK --restore-mark\n-A PREROUTING -m comment --comment tsunagi-exit-sockets:tsun0 -j MARK\n-A PREROUTING -m comment --comment tsunagi-exit-sockets:tsun1 -j MARK\n".into(), stderr: String::new() }
        };
        refresh(&run, "tsun0", false, &sockets).unwrap();
        let calls = calls.borrow();
        assert!(
            calls
                .iter()
                .any(|(_, a)| a.contains("-I PREROUTING 1") && a.contains("-p udp"))
        );
        assert!(
            calls
                .iter()
                .filter(|(_, a)| a.contains("-D"))
                .all(|(_, a)| a.contains("tsunagi-exit-sockets:tsun0"))
        );
    }
}
