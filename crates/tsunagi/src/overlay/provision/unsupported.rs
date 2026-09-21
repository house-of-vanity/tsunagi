//! The provisioner for platforms that do not have one yet.
//!
//! macOS and Windows both need real work here — `utun` plus the
//! `SystemConfiguration` framework on one, the IP Helper API and a Wintun
//! adapter on the other — and neither is written. Rather than let the agent
//! come up and fail obscurely at the first packet, this refuses at the point
//! of provisioning and says what to do instead.

use crate::BoxFuture;
use crate::overlay::OverlayError;

use super::{InterfacePlan, InterfaceProvisioner, Provisioned};

/// Refuses to provision, with an explanation.
#[derive(Debug, Clone)]
pub struct UnsupportedProvisioner {
    platform: &'static str,
}

impl Default for UnsupportedProvisioner {
    fn default() -> Self {
        Self::new()
    }
}

impl UnsupportedProvisioner {
    /// A provisioner naming the platform it is standing in for.
    pub fn new() -> Self {
        Self {
            platform: std::env::consts::OS,
        }
    }

    fn refusal(&self) -> OverlayError {
        OverlayError::Unavailable(format!(
            "managing the overlay interface is not implemented on {} yet. \
             Run with `--no-tun` until it is: the tunnels still form, they just \
             do not reach the operating system.",
            self.platform
        ))
    }
}

impl InterfaceProvisioner for UnsupportedProvisioner {
    fn name(&self) -> &str {
        "unsupported"
    }

    fn reconcile<'a>(
        &'a self,
        _plan: &'a InterfacePlan,
    ) -> BoxFuture<'a, Result<Provisioned, OverlayError>> {
        Box::pin(async move { Err(self.refusal()) })
    }

    fn remove<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<(), OverlayError>> {
        // Nothing was ever created, so there is nothing to clean up and no
        // reason to fail a shutdown path.
        Box::pin(async move { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[tokio::test]
    async fn it_refuses_with_a_usable_pointer_and_still_cleans_up_quietly() {
        let provisioner = UnsupportedProvisioner::new();
        let plan = InterfacePlan::new("tsuntest", 1280, Vec::new());
        let err = provisioner.reconcile(&plan).await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("--no-tun"), "{message}");
        assert!(message.contains(std::env::consts::OS), "{message}");

        provisioner.remove("tsuntest").await.unwrap();
    }
}
