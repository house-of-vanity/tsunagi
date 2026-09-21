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

fn start(network: &str, port: u16) -> Running {
    let dir = TempDir::new().unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_tsunagi"))
        .args([
            "up",
            "--network",
            network,
            "--secret",
            "a-secret-for-the-cli-test",
        ])
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--cache-dir")
        .arg(dir.path().join("cache"))
        .args(["--reach", "local", "--no-tun"])
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .args(["--log", "error", "--status-interval", "0"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the agent binary starts");
    // Long enough for the control socket to be there to talk to.
    std::thread::sleep(Duration::from_secs(2));
    Running { child, dir }
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
        .find(|line| line.contains("tsunagi up --network spontaneous"))
        .expect("a command to send");
    assert!(command.contains(secret), "with the secret in it: {out}");
    assert!(
        command.contains("--peer "),
        "and somewhere to find us: {out}"
    );

    // Joining the same name again resumes it rather than making another
    // network that merely looks the same.
    let again = agent.run(&["network", "join", "--network", "spontaneous"]);
    let out = String::from_utf8_lossy(&again.stdout);
    assert!(again.status.success());
    assert!(out.contains("already configured"), "{out}");
    assert!(!out.contains("secret  tsn1"), "no second secret: {out}");
}

#[test]
fn a_bare_name_resumes_the_network_of_that_name_rather_than_inventing_one() {
    // `up --network resident` with no secret is the same rule: this device
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
    assert!(out.contains("already configured"), "{out}");
}
