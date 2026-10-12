//! Making and joining a network from the command line, against a real agent.
//!
//! The rules here are small and easy to get wrong in a way no unit test
//! notices: what a bare network name means, when a secret is invented, and
//! whether what is printed is enough for the other person to paste.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

use tempfile::TempDir;

/// An agent running as a real process, with its own directories.
struct Running {
    child: std::process::Child,
    dir: TempDir,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Running {
    fn run(&self, args: &[&str]) -> std::process::Output {
        run_in(&self.dir, args)
    }
}

fn run_in(dir: &TempDir, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_tsng"))
        .args(args)
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--cache-dir")
        .arg(dir.path().join("cache"))
        .output()
        .expect("the agent binary runs")
}

fn read_networks(dir: &TempDir) -> Vec<tsunagi::storage::StoredNetwork> {
    tsunagi::storage::StateStore::open(dir.path().join("state/state.sqlite"))
        .unwrap()
        .list_networks()
        .unwrap()
}

/// An agent with no network at all, the way a daemon is started before
/// anything has been decided.
fn start_bare(port: u16) -> Running {
    start_bare_range(port, None)
}

fn start_bare_range(port: u16, range: Option<&str>) -> Running {
    start_bare_config(port, range, None)
}

fn start_bare_config(port: u16, range: Option<&str>, protocols: Option<&str>) -> Running {
    let dir = TempDir::new().unwrap();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_tsng"));
    command
        .arg("up")
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--cache-dir")
        .arg(dir.path().join("cache"))
        .args(["--reach", "local", "--no-tun", "--no-dns"])
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .args(["--log", "error", "--status-interval", "0"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(range) = range {
        command.args(["--ipv4-range", range]);
    }
    if let Some(protocols) = protocols {
        command.args(["--protocol", protocols]);
    }
    let child = command.spawn().expect("the agent binary starts");
    let mut agent = Running { child, dir };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let socket = tsunagi::ipc::control_socket_path(&agent.dir.path().join("state"));
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !tsunagi::ipc::is_serving(&socket).await {
                assert!(
                    agent.child.try_wait().unwrap().is_none(),
                    "agent exited before becoming ready"
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("agent becomes ready");
    });
    agent
}

/// An agent already in one network, the way most of these start.
fn start(network: &str, port: u16) -> Running {
    let agent = start_bare(port);
    let joined = agent.run(&[
        "join",
        "--network",
        network,
        "--secret",
        "a-secret-for-the-cli-test",
    ]);
    assert!(
        joined.status.success(),
        "{}",
        String::from_utf8_lossy(&joined.stderr)
    );
    agent
}

#[test]
fn protocols_absent_from_startup_can_be_enabled_and_changed_offline() {
    let mut agent = start_bare_config(0, None, Some("none"));
    assert!(
        agent
            .run(&[
                "join",
                "--network",
                "from-control-only",
                "--secret",
                "a-control-only-test-secret"
            ])
            .status
            .success()
    );
    let initial = agent.run(&["protocols", "from-control-only"]);
    assert!(initial.status.success());
    assert!(String::from_utf8_lossy(&initial.stdout).contains("protocols none"));
    let enabled = agent.run(&["protocols", "from-control-only", "awg"]);
    assert!(
        enabled.status.success(),
        "{}",
        String::from_utf8_lossy(&enabled.stderr)
    );
    assert_eq!(
        read_networks(&agent.dir)[0].protocols,
        Some(vec!["awg".into()])
    );
    agent.child.kill().unwrap();
    agent.child.wait().unwrap();
    let saved = agent.run(&["protocols", "from-control-only", "wg-quic,awg"]);
    assert!(
        saved.status.success(),
        "{}",
        String::from_utf8_lossy(&saved.stderr)
    );
    assert!(String::from_utf8_lossy(&saved.stdout).contains("agent stopped"));
    assert_eq!(
        read_networks(&agent.dir)[0].protocols,
        Some(vec!["wg-quic".into(), "awg".into()])
    );
}

#[test]
fn protocols_are_changed_live_per_network_and_saved_without_changing_the_service() {
    let agent = start("protocol-choice", 0);
    assert!(
        agent
            .run(&[
                "join",
                "--network",
                "other-choice",
                "--secret",
                "other-secret-for-cli-test"
            ])
            .status
            .success()
    );
    let before = read_networks(&agent.dir);
    let other_id = before
        .iter()
        .find(|n| n.name.as_str() == "other-choice")
        .unwrap()
        .network_id;
    let changed = agent.run(&["protocols", "protocol-choice", "awg,wg-quic"]);
    assert!(
        changed.status.success(),
        "{}",
        String::from_utf8_lossy(&changed.stderr)
    );
    let shown = agent.run(&["protocols", "protocol-choice"]);
    assert!(shown.status.success());
    assert!(String::from_utf8_lossy(&shown.stdout).contains("awg,wg-quic"));
    let saved = read_networks(&agent.dir);
    assert_eq!(
        saved
            .iter()
            .find(|n| n.name.as_str() == "protocol-choice")
            .unwrap()
            .protocols,
        Some(vec!["awg".into(), "wg-quic".into()])
    );
    assert_eq!(
        saved
            .iter()
            .find(|n| n.network_id == other_id)
            .unwrap()
            .protocols,
        before
            .iter()
            .find(|n| n.network_id == other_id)
            .unwrap()
            .protocols
    );
    for invalid in ["unknown", "awg,awg", "none,awg"] {
        assert!(
            !agent
                .run(&["protocols", "protocol-choice", invalid])
                .status
                .success()
        );
    }
    assert!(!agent.run(&["protocols", "missing", "awg"]).status.success());
    let disabled = agent.run(&["protocols", "protocol-choice", "none"]);
    assert!(
        disabled.status.success(),
        "{}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    assert_eq!(
        read_networks(&agent.dir)
            .iter()
            .find(|n| n.name.as_str() == "protocol-choice")
            .unwrap()
            .protocols,
        Some(Vec::new())
    );
    assert!(
        agent
            .run(&["network", "stop", "protocol-choice"])
            .status
            .success()
    );
    assert!(
        agent
            .run(&["protocols", "protocol-choice", "wg-quic"])
            .status
            .success()
    );
    assert!(
        agent
            .run(&["network", "start", "protocol-choice"])
            .status
            .success()
    );
    assert!(
        String::from_utf8_lossy(&agent.run(&["protocols", "protocol-choice"]).stdout)
            .contains("wg-quic")
    );
}

#[test]
fn joining_with_no_secret_makes_one_and_prints_what_to_send() {
    // The hurry case: a network with somebody, for as long as it is needed,
    // and then gone. Asking for a secret first is a step with no purpose,
    // and a secret that is not printed is a network nobody else can join.
    let agent = start("resident", 45071);

    let joined = agent.run(&["network", "join", "--network", "spontaneous"]);
    assert!(
        joined.status.success(),
        "joining failed: {}",
        String::from_utf8_lossy(&joined.stderr)
    );
    let out = String::from_utf8_lossy(&joined.stdout);
    assert!(out.contains("joined `spontaneous`"), "{out}");

    // The secret in full, and one line the other side can paste as it is.
    let secret = out
        .lines()
        .find_map(|line| line.trim().strip_prefix("secret  "))
        .expect("the invented secret is printed");
    assert!(secret.starts_with("tsn1"), "{out}");
    let command = out
        .lines()
        .find(|line| line.contains("tsng join --network spontaneous"))
        .expect("a command to send");
    assert!(command.contains(secret), "with the secret in it: {out}");
    // And where to find this device, for an agent that is not up yet.
    assert!(out.contains("--peer "), "somewhere to find us: {out}");

    // Joining the same name again resumes it rather than making another
    // network that merely looks the same.
    let again = agent.run(&["network", "join", "--network", "spontaneous"]);
    let out = String::from_utf8_lossy(&again.stdout);
    assert!(again.status.success());
    assert!(out.contains("already here"), "{out}");
    assert!(!out.contains("secret  tsn1"), "no second secret: {out}");
}

#[test]
fn a_bare_name_resumes_the_network_of_that_name_rather_than_inventing_one() {
    // `join --network resident` with no secret is the same rule: this device
    // has exactly one network of that name, so that is the one meant.
    let agent = start("resident", 45072);
    let listed = agent.run(&["network"]);
    let before = String::from_utf8_lossy(&listed.stdout).to_string();
    let id = before
        .lines()
        .find(|line| line.contains("resident"))
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("the network is listed")
        .to_string();

    let joined = agent.run(&["network", "join", "--network", "resident"]);
    assert!(joined.status.success());
    let out = String::from_utf8_lossy(&joined.stdout);
    assert!(out.contains(&id), "the same network, not a new one: {out}");
    assert!(out.contains("already here"), "{out}");
}

#[test]
fn a_network_can_be_stopped_and_resumed_without_losing_anything() {
    // Leaving gives everything up; stopping is being away. The difference
    // is what somebody wants when they will be back.
    let agent = start("resident", 45073);
    let listed = agent.run(&["network"]);
    let out = String::from_utf8_lossy(&listed.stdout).to_string();
    let id = out
        .lines()
        .find(|line| line.contains("resident"))
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("the network is listed")
        .to_string();
    let secret_before = agent.run(&["network", "secret", &id[..10]]);
    let secret_before = String::from_utf8_lossy(&secret_before.stdout)
        .trim()
        .to_string();
    assert!(secret_before.starts_with("tsn1"));

    let stopped = agent.run(&["network", "stop", "resident"]);
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(
        String::from_utf8_lossy(&stopped.stdout).contains("stopped `resident`"),
        "{}",
        String::from_utf8_lossy(&stopped.stdout)
    );

    // Still configured, and said to be stopped rather than missing.
    let listed = String::from_utf8_lossy(&agent.run(&["network"]).stdout).to_string();
    assert!(listed.contains(&id), "still configured: {listed}");
    assert!(listed.contains("stopped"), "{listed}");

    // Stopping what is stopped is the state asked for, not an error.
    let again = agent.run(&["network", "stop", &id[..10]]);
    assert!(again.status.success());
    assert!(
        String::from_utf8_lossy(&again.stdout).contains("already stopped"),
        "{}",
        String::from_utf8_lossy(&again.stdout)
    );

    let started = agent.run(&["network", "start", "resident"]);
    assert!(started.status.success());
    assert!(
        String::from_utf8_lossy(&started.stdout).contains("started `resident`"),
        "{}",
        String::from_utf8_lossy(&started.stdout)
    );
    let listed = String::from_utf8_lossy(&agent.run(&["network"]).stdout).to_string();
    assert!(listed.contains("running"), "{listed}");

    // And nothing was given up on the way: the same network, same secret.
    let secret_after = agent.run(&["network", "secret", "resident"]);
    assert_eq!(
        String::from_utf8_lossy(&secret_after.stdout).trim(),
        secret_before,
        "the secret is kept, so this is the same network"
    );
}

#[test]
fn an_agent_starts_with_no_network_and_takes_one_later() {
    // A daemon in one terminal and the deciding done in another: the
    // agent is the identity, and which networks it is in is a separate
    // question it can answer at any time.
    let agent = start_bare(45074);

    let listed = agent.run(&["network"]);
    assert!(listed.status.success());
    assert!(
        String::from_utf8_lossy(&listed.stderr).contains("no network has been joined"),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );

    let joined = agent.run(&["network", "join", "--network", "afterwards"]);
    assert!(
        joined.status.success(),
        "{}",
        String::from_utf8_lossy(&joined.stderr)
    );
    let listed = String::from_utf8_lossy(&agent.run(&["network"]).stdout).to_string();
    assert!(listed.contains("afterwards"), "{listed}");
    assert!(listed.contains("running"), "and it is live: {listed}");
}

#[test]
fn up_is_the_agent_and_takes_no_network_at_all() {
    // The two commands are separate on purpose: `up` runs the device's
    // agent, `join` decides what it is in. A network on `up` would be a
    // second way to do the same thing, and the one that cannot be undone
    // without a restart.
    for argument in ["--network", "--secret"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_tsng"))
            .args(["up", argument, "whatever"])
            .arg("--state-dir")
            .arg(TempDir::new().unwrap().path().join("state"))
            .output()
            .expect("the agent binary runs");
        assert!(
            !out.status.success(),
            "`up {argument}` should not be a thing"
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("unexpected argument"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
#[test]
fn broadcast_choice_is_per_network_live_persistent_and_preserved_by_rejoin() {
    let agent = start_bare(0);
    for args in [
        vec!["join", "-n", "broadcast-default"],
        vec!["join", "-n", "broadcast-off", "--no-broadcast"],
    ] {
        let result = agent.run(&args);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let read = || {
        tsunagi::storage::StateStore::open(agent.dir.path().join("state/state.sqlite"))
            .unwrap()
            .list_networks()
            .unwrap()
    };
    let networks = read();
    let enabled = networks
        .iter()
        .find(|n| n.name.as_str() == "broadcast-default")
        .unwrap();
    let disabled = networks
        .iter()
        .find(|n| n.name.as_str() == "broadcast-off")
        .unwrap();
    assert!(enabled.broadcast);
    assert!(!disabled.broadcast);
    assert!(agent.run(&["join", "-n", "broadcast-off"]).status.success());
    assert!(
        !read()
            .iter()
            .find(|n| n.name.as_str() == "broadcast-off")
            .unwrap()
            .broadcast
    );
    let id = disabled.network_id.to_string();
    let change = agent.run(&["network", "broadcast", "broadcast-off", "on"]);
    assert!(
        change.status.success(),
        "{}",
        String::from_utf8_lossy(&change.stderr)
    );
    assert!(read().iter().all(|n| n.broadcast));
    let change = agent.run(&["join", "-n", "broadcast-off", "--no-broadcast"]);
    assert!(
        change.status.success(),
        "{}",
        String::from_utf8_lossy(&change.stderr)
    );
    let status = agent.run(&["network", "broadcast", &id]);
    assert!(String::from_utf8_lossy(&status.stdout).contains("broadcast off"));
    assert!(
        !agent
            .run(&["join", "-n", "conflict", "--broadcast", "--no-broadcast"])
            .status
            .success()
    );
}

#[test]
fn leaving_by_name_removes_only_that_network_from_a_running_agent() {
    let agent = start("resident", 0);
    assert!(agent.run(&["join", "-n", "games"]).status.success());
    let resident = read_networks(&agent.dir)
        .into_iter()
        .find(|network| network.name.as_str() == "resident")
        .unwrap();

    let left = agent.run(&["network", "leave", "games"]);
    assert!(
        left.status.success(),
        "{}",
        String::from_utf8_lossy(&left.stderr)
    );
    assert!(String::from_utf8_lossy(&left.stdout).contains("left `games`"));
    let remaining = read_networks(&agent.dir);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].network_id, resident.network_id);
    assert_eq!(
        remaining[0].secret.encode().as_str(),
        resident.secret.encode().as_str()
    );
    let status = agent.run(&["network"]);
    assert!(status.status.success());
    let out = String::from_utf8_lossy(&status.stdout);
    assert!(out.contains("resident") && out.contains("running"), "{out}");
    assert!(!out.contains("games"), "{out}");
}

#[test]
fn leaving_by_name_offline_keeps_the_explicit_offline_requirement() {
    let dir = TempDir::new().unwrap();
    for name in ["resident", "games"] {
        assert!(run_in(&dir, &["join", "-n", name]).status.success());
    }
    let refused = run_in(&dir, &["network", "leave", "games"]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--offline"));
    assert_eq!(read_networks(&dir).len(), 2);

    let left = run_in(&dir, &["network", "leave", "games", "--offline"]);
    assert!(
        left.status.success(),
        "{}",
        String::from_utf8_lossy(&left.stderr)
    );
    let remaining = read_networks(&dir);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].name.as_str(), "resident");
}

#[test]
fn ambiguous_and_unknown_names_leave_every_network_untouched() {
    let agent = start_bare(0);
    for secret in [
        "first-secret-for-the-cli-test",
        "second-secret-for-the-cli-test",
    ] {
        assert!(
            agent
                .run(&["join", "-n", "games", "-s", secret])
                .status
                .success()
        );
    }
    let before = read_networks(&agent.dir);
    assert_eq!(before.len(), 2);
    for name in ["games", "missing-network"] {
        let result = agent.run(&["network", "leave", name]);
        assert!(!result.status.success());
        let err = String::from_utf8_lossy(&result.stderr);
        if name == "games" {
            assert!(err.contains("matches 2 networks"), "{err}");
            for network in &before {
                assert!(err.contains(&network.network_id.to_string()), "{err}");
                assert!(!err.contains(network.secret.encode().as_str()), "{err}");
            }
        } else {
            assert!(err.contains("no configured network"), "{err}");
        }
        assert_eq!(read_networks(&agent.dir).len(), 2);
    }
    // The suggested full id still selects exactly one of the same-name networks.
    let left = agent.run(&["network", "leave", &before[0].network_id.to_string()]);
    assert!(
        left.status.success(),
        "{}",
        String::from_utf8_lossy(&left.stderr)
    );
    let remaining = read_networks(&agent.dir);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].network_id, before[1].network_id);
}

#[test]
fn an_exit_node_is_offered_per_network_only_when_asked_and_nobody_offers_by_default() {
    let agent = start_bare(0);
    assert!(agent.run(&["join", "-n", "exit-offer"]).status.success());
    let offered = || {
        read_networks(&agent.dir)
            .iter()
            .find(|n| n.name.as_str() == "exit-offer")
            .unwrap()
            .exit_node
    };
    assert!(!offered(), "off unless somebody turns it on");

    let on = agent.run(&["network", "exit-node", "exit-offer", "on"]);
    assert!(
        on.status.success(),
        "{}",
        String::from_utf8_lossy(&on.stderr)
    );
    assert!(String::from_utf8_lossy(&on.stdout).contains("exit node on"));
    assert!(offered());

    let off = agent.run(&["network", "exit-node", "exit-offer", "off"]);
    assert!(off.status.success());
    assert!(!offered());

    let listed = agent.run(&["exit-node"]);
    assert!(listed.status.success());
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("no connected device offers"),
        "{}",
        String::from_utf8_lossy(&listed.stdout)
    );

    let unknown = agent.run(&["exit-node", "nobody"]);
    assert!(!unknown.status.success());
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("no connected device matches"),
        "{}",
        String::from_utf8_lossy(&unknown.stderr)
    );
}

#[test]
fn overlapping_networks_are_reported_and_cli_start_switches_then_resumes() {
    let agent = start_bare_range(0, Some("10.90.0.0/16"));
    for name in ["resident", "games"] {
        let joined = agent.run(&["join", "-n", name, "-s", "a-secret-for-the-conflict-test"]);
        assert!(
            joined.status.success(),
            "{}",
            String::from_utf8_lossy(&joined.stderr)
        );
        if name == "games" {
            let text = String::from_utf8_lossy(&joined.stdout);
            assert!(
                text.contains("stopped because its range overlaps"),
                "{text}"
            );
            assert!(!text.contains("it is running"), "{text}");
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let socket = tsunagi::ipc::control_socket_path(&agent.dir.path().join("state"));
    let snapshot = || {
        runtime
            .block_on(tsunagi::ipc::request_status(&socket))
            .unwrap()
    };
    let before = snapshot();
    let resident = before
        .networks
        .iter()
        .find(|n| n.name == "resident")
        .unwrap();
    let games = before.networks.iter().find(|n| n.name == "games").unwrap();
    assert!(resident.active);
    assert!(!games.active);
    assert_eq!(games.range_conflicts[0].network_id, resident.network_id);
    assert_eq!(games.range_conflicts[0].name, "resident");
    for args in [vec!["status"], vec!["network"]] {
        let result = agent.run(&args);
        let text = String::from_utf8_lossy(&result.stdout);
        assert!(text.contains("range conflict"), "{text}");
        assert!(text.contains(&resident.network_id), "{text}");
        assert!(text.contains("tsng network start"), "{text}");
    }
    let switched = agent.run(&["network", "start", "games"]);
    assert!(
        switched.status.success(),
        "{}",
        String::from_utf8_lossy(&switched.stderr)
    );
    let text = String::from_utf8_lossy(&switched.stdout);
    assert!(
        text.contains("started `games`") && text.contains("suspended `resident`"),
        "{text}"
    );
    let after = snapshot();
    assert!(
        after
            .networks
            .iter()
            .find(|n| n.name == "games")
            .unwrap()
            .active
    );
    assert!(
        !after
            .networks
            .iter()
            .find(|n| n.name == "resident")
            .unwrap()
            .active
    );
    assert!(agent.run(&["network", "stop", "games"]).status.success());
    assert!(
        snapshot()
            .networks
            .iter()
            .find(|n| n.name == "resident")
            .unwrap()
            .active
    );

    assert!(agent.run(&["network", "start", "games"]).status.success());
    let stop_suspended = agent.run(&["network", "stop", "resident"]);
    assert!(stop_suspended.status.success());
    assert!(String::from_utf8_lossy(&stop_suspended.stdout).contains("stopped `resident`"));
    assert!(agent.run(&["network", "stop", "games"]).status.success());
    assert!(
        snapshot()
            .networks
            .iter()
            .all(|n| !n.active && !n.auto_start)
    );
}

#[test]
fn cli_defaults_derive_each_networks_range() {
    let agent = start_bare(0);
    for name in ["derived-one", "derived-two"] {
        assert!(
            agent
                .run(&["join", "-n", name, "-s", "a-secret-for-the-derived-test"])
                .status
                .success()
        );
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let socket = tsunagi::ipc::control_socket_path(&agent.dir.path().join("state"));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let report = runtime
            .block_on(tsunagi::ipc::request_status(&socket))
            .unwrap();
        if report.networks.iter().all(|n| n.range.is_some()) {
            assert_eq!(report.networks.len(), 2);
            for network in report.networks {
                let id = network.network_id.parse().unwrap();
                assert!(network.active);
                assert_eq!(
                    network.range,
                    Some(tsunagi::state::derived_ipv4_range(id).to_string())
                );
            }
            break;
        }
        assert!(Instant::now() < deadline, "networks allocate ranges");
        std::thread::sleep(Duration::from_millis(25));
    }
}
