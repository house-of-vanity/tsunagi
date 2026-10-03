//! What the command line says about this device, against a running agent.
//!
//! These drive the real binary, which is why they live beside it rather
//! than with the library's own tests: the library cannot depend on a binary
//! built from a crate that depends on it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;
use tsunagi::Agent;
use tsunagi::config::{AgentConfig, StoragePaths, TransportPolicy};

/// Asking who this device is must not need the directory lock.
///
/// The lock belongs to the one agent allowed to *write* the state. `id` only
/// reads, so making it take the lock would mean the question could never be
/// answered while an agent was running — which is exactly when you want to
/// ask it.
#[tokio::test]
async fn identity_can_be_read_while_an_agent_holds_the_directory() {
    let dir = TempDir::new().unwrap();

    // Hold the directory the way a running agent does.
    let agent = Agent::spawn(
        AgentConfig::new(StoragePaths::under(dir.path()))
            .with_transport(TransportPolicy::LocalOnly)
            .with_loopback_bind(),
    )
    .await
    .unwrap();
    let expected = agent.endpoint_id().to_string();

    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_tsng"))
        .arg("id")
        // The same layout `StoragePaths::under` gives the agent above.
        .arg("--state-dir")
        .arg(dir.path().join("state"))
        .arg("--cache-dir")
        .arg(dir.path().join("cache"))
        .output()
        .await
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "`id` failed while an agent was running:\n{stderr}"
    );
    assert!(
        stdout.contains(&expected),
        "expected {expected} in:\n{stdout}"
    );

    agent.shutdown().await;
}
