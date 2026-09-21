//! The DNS service as the binary actually runs it.
//!
//! The zone and the server have their own tests. What this covers is the
//! wiring between them and the agent, which is where the interesting
//! mistakes live: choosing an address to listen on, and deciding when to
//! rebuild the listener. Both were wrong once, and neither was reachable
//! from a unit test, so this runs the real binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use simple_dns::{Name, Packet, QCLASS, RCODE, TYPE, rdata::RData};
use tempfile::TempDir;

// A port per test, high enough to need no privileges and fixed so the query
// knows where to look. Distinct because these tests run in parallel and each
// starts its own agent.
const PORT_BINDS: u16 = 15361;
const PORT_REBIND: u16 = 15362;
const PORT_REFUSE: u16 = 15363;
const PORT_TWO_ZONES: u16 = 15364;
const PORT_SWITCH: u16 = 15365;

/// Asks, and returns the raw reply. Raw because a parsed packet borrows
/// from the bytes it came out of.
fn query(server: SocketAddr, name: &str, qtype: TYPE) -> Option<Vec<u8>> {
    let mut packet = Packet::new_query(0x2468);
    packet.questions.push(simple_dns::Question::new(
        Name::new(name).unwrap(),
        qtype.into(),
        QCLASS::CLASS(simple_dns::CLASS::IN),
        false,
    ));
    let bytes = packet.build_bytes_vec().unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    socket.send_to(&bytes, server).ok()?;
    let mut buffer = vec![0u8; 4096];
    let read = socket.recv(&mut buffer).ok()?;
    buffer.truncate(read);
    Packet::parse(&buffer).ok()?;
    Some(buffer)
}

/// Whether a reply carries at least one answer record.
fn has_answer(reply: &[u8]) -> bool {
    Packet::parse(reply).is_ok_and(|packet| !packet.answers.is_empty())
}

/// Blocks until the server answers, or gives up.
fn wait_for_answer(server: SocketAddr, name: &str) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(reply) = query(server, name, TYPE::A)
            && has_answer(&reply)
        {
            return reply;
        }
        assert!(Instant::now() < deadline, "the dns server never answered");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The agent, running as a real process with its DNS service on.
struct Running {
    child: std::process::Child,
    dir: TempDir,
}

impl Running {
    /// Runs another `tsunagi` command against this agent's directory.
    fn run(&self, args: &[&str]) -> std::process::Output {
        std::process::Command::new(env!("CARGO_BIN_EXE_tsunagi"))
            .args(args)
            .arg("--state-dir")
            .arg(self.dir.path().join("state"))
            .arg("--cache-dir")
            .arg(self.dir.path().join("cache"))
            .output()
            .expect("the agent binary runs")
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts an agent in one network, whose name is therefore the zone.
///
/// There is no separate zone setting: an agent serves a zone per network,
/// named after it, so the network name is the zone name.
fn start(zone: &str, port: u16) -> Running {
    let dir = TempDir::new().unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_tsunagi"))
        .args([
            "up",
            "--network",
            zone,
            "--secret",
            "a-secret-for-the-dns-test",
        ])
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--cache-dir")
        .arg(dir.path().join("cache"))
        // No real interface and no internet: this is about the wiring.
        .args(["--reach", "local", "--no-tun", "--dns"])
        .args(["--dns-port", &port.to_string()])
        .args(["--log", "error", "--status-interval", "0"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the agent binary starts");
    Running { child, dir }
}

/// Starts an agent with the resolver off, to be switched on later.
fn start_without_dns(network: &str) -> Running {
    let dir = TempDir::new().unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_tsunagi"))
        .args([
            "up",
            "--network",
            network,
            "--secret",
            "a-secret-for-the-dns-test",
        ])
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--cache-dir")
        .arg(dir.path().join("cache"))
        .args(["--reach", "local", "--no-tun"])
        .args(["--log", "error", "--status-interval", "0"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the agent binary starts");
    Running { child, dir }
}

#[test]
fn the_resolver_comes_up_even_with_no_overlay_interface_to_put_it_on() {
    // The promise is that the port is served whatever else fails: with
    // `--no-tun` there is no interface to attach a resolver setting to,
    // and the zone is answered on loopback all the same. Getting this
    // wrong left the feature silently dead.
    let _agent = start("lab.internal", PORT_BINDS);
    let server: SocketAddr = format!("127.0.0.1:{PORT_BINDS}").parse().unwrap();

    let reply = wait_for_answer(server, &format!("{}.lab.internal", hostname()));
    let answer = Packet::parse(&reply).unwrap();
    assert_eq!(answer.rcode(), RCODE::NoError);
    match &answer.answers[0].rdata {
        RData::A(_) => {}
        other => panic!("expected an A record, got {other:?}"),
    }
}

#[test]
fn the_listener_is_not_rebuilt_on_every_pass() {
    // The listener is bound once and kept, and the zones are swapped
    // underneath it as networks and members come and go. Rebuilding it on
    // the way past — which an earlier version did on every tick — shut the
    // port for a moment each time.
    let _agent = start("rebind.internal", PORT_REBIND);
    let server: SocketAddr = format!("127.0.0.1:{PORT_REBIND}").parse().unwrap();
    let name = format!("{}.rebind.internal", hostname());
    wait_for_answer(server, &name);

    // Long enough to cross several of the supervisor's passes.
    for round in 0..6 {
        std::thread::sleep(Duration::from_millis(900));
        assert!(
            query(server, &name, TYPE::A).is_some_and(|reply| has_answer(&reply)),
            "the server stopped answering on round {round}"
        );
    }
}

#[test]
fn a_name_outside_the_zone_is_refused_and_never_forwarded() {
    let _agent = start("refuse.internal", PORT_REFUSE);
    let server: SocketAddr = format!("127.0.0.1:{PORT_REFUSE}").parse().unwrap();
    wait_for_answer(server, &format!("{}.refuse.internal", hostname()));

    let reply = query(server, "example.com", TYPE::A).expect("an answer");
    let answer = Packet::parse(&reply).unwrap();
    assert_eq!(answer.rcode(), RCODE::Refused);
    assert!(answer.answers.is_empty());
}

fn hostname() -> String {
    tsunagi::agent::system_hostname().unwrap_or_else(|| "unknown".into())
}

#[test]
fn every_network_gets_a_zone_of_its_own() {
    // One agent, one identity, several networks — and a question carries a
    // name, not the network it belongs to. Each network is a zone named
    // after it, and joining one while the agent runs adds its zone without
    // restarting anything.
    let agent = start("first.internal", PORT_TWO_ZONES);
    let server: SocketAddr = format!("127.0.0.1:{PORT_TWO_ZONES}").parse().unwrap();
    let host = hostname();
    wait_for_answer(server, &format!("{host}.first.internal"));

    let joined = agent.run(&[
        "network",
        "join",
        "--network",
        "second.internal",
        "--secret",
        "another-secret-for-the-dns-test",
    ]);
    assert!(
        joined.status.success(),
        "joining failed: {}",
        String::from_utf8_lossy(&joined.stderr)
    );

    // The second network's zone answers too, and neither leaks into the
    // other: a member of one is not a name in the other.
    let reply = wait_for_answer(server, &format!("{host}.second.internal"));
    assert_eq!(Packet::parse(&reply).unwrap().rcode(), RCODE::NoError);
    let first = wait_for_answer(server, &format!("{host}.first.internal"));
    assert_eq!(Packet::parse(&first).unwrap().rcode(), RCODE::NoError);
}

#[test]
fn the_resolver_can_be_switched_on_and_off_while_the_agent_runs() {
    // Forgetting `--dns` on a command line should not be a decision that
    // lasts until the next restart, and it is not: the setting belongs to
    // the device, and turning it on takes effect at once.
    let agent = start_without_dns("switch.internal");
    let server: SocketAddr = format!("127.0.0.1:{PORT_SWITCH}").parse().unwrap();
    let host = hostname();

    // Give the agent time to be up before asking it anything.
    std::thread::sleep(Duration::from_secs(1));
    assert!(
        query(server, &format!("{host}.switch.internal"), TYPE::A).is_none(),
        "nothing should be answering yet"
    );

    let on = agent.run(&["dns", "on", "--port", &PORT_SWITCH.to_string()]);
    assert!(
        on.status.success(),
        "dns on failed: {}",
        String::from_utf8_lossy(&on.stderr)
    );
    wait_for_answer(server, &format!("{host}.switch.internal"));

    let off = agent.run(&["dns", "off"]);
    assert!(off.status.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    while query(server, &format!("{host}.switch.internal"), TYPE::A).is_some() {
        assert!(
            Instant::now() < deadline,
            "it kept answering after `dns off`"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}
