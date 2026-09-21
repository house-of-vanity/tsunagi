//! How a desired configuration reaches the operating system.
//!
//! The plugin computes *what* the interface should look like; a backend makes
//! it so. Splitting them keeps every interesting decision testable without
//! root and without touching the host's network.
//!
//! A backend only ever touches the interface named in the configuration it is
//! given. It never enumerates, adopts or modifies anything else.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::dataplane::PluginError;

use super::config::{InterfaceConfig, InterfaceState};

/// Applies a desired WireGuard configuration.
///
/// Implementations are synchronous and may block; the plugin calls them from a
/// blocking task, never from the async runtime.
pub trait WireguardBackend: Send + Sync + std::fmt::Debug + 'static {
    /// A short name used in diagnostics.
    fn name(&self) -> &str;

    /// Reads back the current state of an interface.
    ///
    /// `Ok(None)` means the interface does not exist, which is different from
    /// an error.
    fn inspect(&self, interface: &str) -> Result<Option<InterfaceState>, PluginError>;

    /// Creates or updates the interface so that it matches `desired`.
    fn apply(&self, desired: &InterfaceConfig) -> Result<(), PluginError>;

    /// Removes an interface this plugin created. Removing an absent interface
    /// succeeds.
    fn remove(&self, interface: &str) -> Result<(), PluginError>;
}

/// What a [`RecordingBackend`] was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendCall {
    /// An interface was inspected.
    Inspect(String),
    /// An interface was created or updated.
    Apply(String),
    /// An interface was removed.
    Remove(String),
}

/// An in-memory backend for tests and dry runs.
///
/// It behaves like a working WireGuard implementation without needing root or
/// touching the host: applied configurations are remembered and can be read
/// back, drift can be injected, and failures can be simulated.
#[derive(Debug, Clone, Default)]
pub struct RecordingBackend {
    inner: Arc<Mutex<Recorded>>,
}

#[derive(Debug, Default)]
struct Recorded {
    interfaces: HashMap<String, InterfaceState>,
    calls: Vec<BackendCall>,
    fail_next_apply: Option<String>,
}

impl RecordingBackend {
    /// Creates an empty backend.
    pub fn new() -> Self {
        Self::default()
    }

    fn with<T>(&self, f: impl FnOnce(&mut Recorded) -> T) -> T {
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut guard)
    }

    /// The state currently configured for an interface, if any.
    pub fn state(&self, interface: &str) -> Option<InterfaceState> {
        self.with(|recorded| recorded.interfaces.get(interface).cloned())
    }

    /// Every interface currently configured.
    pub fn interfaces(&self) -> Vec<String> {
        self.with(|recorded| {
            let mut names: Vec<String> = recorded.interfaces.keys().cloned().collect();
            names.sort();
            names
        })
    }

    /// Everything the backend was asked to do, in order.
    pub fn calls(&self) -> Vec<BackendCall> {
        self.with(|recorded| recorded.calls.clone())
    }

    /// How many times an interface was applied.
    pub fn apply_count(&self, interface: &str) -> usize {
        self.with(|recorded| {
            recorded
                .calls
                .iter()
                .filter(|call| matches!(call, BackendCall::Apply(name) if name == interface))
                .count()
        })
    }

    /// Replaces an interface's state, simulating someone editing it by hand.
    pub fn inject_drift(&self, interface: &str, state: InterfaceState) {
        self.with(|recorded| {
            recorded.interfaces.insert(interface.to_string(), state);
        });
    }

    /// Makes the next `apply` fail, simulating a data plane error.
    pub fn fail_next_apply(&self, reason: impl Into<String>) {
        let reason = reason.into();
        self.with(|recorded| recorded.fail_next_apply = Some(reason));
    }

    /// Forgets the recorded call history, keeping configured interfaces.
    pub fn clear_calls(&self) {
        self.with(|recorded| recorded.calls.clear());
    }
}

impl WireguardBackend for RecordingBackend {
    fn name(&self) -> &str {
        "recording"
    }

    fn inspect(&self, interface: &str) -> Result<Option<InterfaceState>, PluginError> {
        self.with(|recorded| {
            recorded
                .calls
                .push(BackendCall::Inspect(interface.to_string()));
            Ok(recorded.interfaces.get(interface).cloned())
        })
    }

    fn apply(&self, desired: &InterfaceConfig) -> Result<(), PluginError> {
        let state = desired.to_state();
        self.with(|recorded| {
            recorded
                .calls
                .push(BackendCall::Apply(desired.name.clone()));
            if let Some(reason) = recorded.fail_next_apply.take() {
                return Err(PluginError::Unavailable(reason));
            }
            recorded.interfaces.insert(desired.name.clone(), state);
            Ok(())
        })
    }

    fn remove(&self, interface: &str) -> Result<(), PluginError> {
        self.with(|recorded| {
            recorded
                .calls
                .push(BackendCall::Remove(interface.to_string()));
            recorded.interfaces.remove(interface);
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::dataplane::wireguard::config::{InterfaceParams, build_interface};
    use crate::dataplane::wireguard::keys::WgSecretKey;
    use crate::identity::{NetworkKeys, NetworkName, NetworkSecret};

    #[test]
    fn the_recording_backend_behaves_like_a_working_one() {
        let network = NetworkKeys::derive(
            &NetworkName::new("backend").unwrap(),
            &NetworkSecret::from_bytes(vec![2u8; 32]).unwrap(),
        )
        .network_id();
        let backend = RecordingBackend::new();
        let config = build_interface(
            InterfaceParams {
                network,
                name: "tsun0".into(),
                private_key: WgSecretKey::generate(),
                listen_port: 51820,
                mtu: None,
                keepalive: None,
            },
            [WgSecretKey::generate().public()],
            |_| None,
        );

        assert_eq!(backend.inspect("tsun0").unwrap(), None);
        backend.apply(&config).unwrap();
        assert_eq!(backend.inspect("tsun0").unwrap(), Some(config.to_state()));
        assert_eq!(backend.interfaces(), vec!["tsun0".to_string()]);

        backend.fail_next_apply("no permission");
        assert!(backend.apply(&config).is_err());
        backend.apply(&config).unwrap();

        backend.remove("tsun0").unwrap();
        assert_eq!(backend.inspect("tsun0").unwrap(), None);
        // Removing something absent is not an error.
        backend.remove("tsun0").unwrap();
        assert_eq!(backend.apply_count("tsun0"), 3);
    }
}
