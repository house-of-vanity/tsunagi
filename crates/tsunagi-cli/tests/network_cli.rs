//! Making and joining a network from the command line, against a real agent.
//!
//! The rules here are small and easy to get wrong in a way no unit test
//! notices: what a bare network name means, when a secret is invented, and
//! whether what is printed is enough for the other person to paste.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

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

/// An agent with no network at all, the way a daemon is started before
/// anything has been decided.
fn start_bare(port: u16) -> Running {
    let dir = TempDir::new().unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_tsunagi"))
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
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the agent binary starts");
    std::thread::sleep(Duration::from_secs(2));
    Running { child, dir }
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
        .find(|line| line.contains("tsunagi join --network spontaneous"))
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

    let stopped = agent.run(&["network", "stop", &id[..10]]);
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

    let started = agent.run(&["network", "start", &id[..10]]);
    assert!(started.status.success());
    assert!(
        String::from_utf8_lossy(&started.stdout).contains("started `resident`"),
        "{}",
        String::from_utf8_lossy(&started.stdout)
    );
    let listed = String::from_utf8_lossy(&agent.run(&["network"]).stdout).to_string();
    assert!(listed.contains("running"), "{listed}");

    // And nothing was given up on the way: the same network, same secret.
    let secret_after = agent.run(&["network", "secret", &id[..10]]);
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
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_tsunagi"))
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
    let change = agent.run(&["network", "broadcast", &id, "on"]);
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
