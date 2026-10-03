//! The publisher for systems nobody has written one for.
//!
//! macOS needs `SystemConfiguration` and Windows the IP Helper API, and
//! neither is written. Saying so is more use than appearing to work: the
//! server is already answering, so all that is missing is the last step, and
//! the user can take it by hand once they know that is what is needed.

use crate::BoxFuture;

use super::{DnsPublisher, PublishError, Published};

/// Refuses to configure anything, with an explanation.
#[derive(Debug, Clone)]
pub struct UnsupportedPublisher {
    platform: &'static str,
}

impl Default for UnsupportedPublisher {
    fn default() -> Self {
        Self::new()
    }
}

impl UnsupportedPublisher {
    /// A publisher naming the platform it stands in for.
    pub fn new() -> Self {
        Self {
            platform: std::env::consts::OS,
        }
    }
}

impl DnsPublisher for UnsupportedPublisher {
    fn name(&self) -> &str {
        "unsupported"
    }

    fn apply<'a>(&'a self, _published: &'a Published) -> BoxFuture<'a, Result<(), PublishError>> {
        Box::pin(async move {
            Err(PublishError::Unavailable(format!(
                "configuring the system resolver is not implemented on {} yet",
                self.platform
            )))
        })
    }

    fn revert(&self) -> BoxFuture<'_, Result<(), PublishError>> {
        // Nothing was set, so there is nothing to undo and no reason to fail
        // a shutdown over it.
        Box::pin(async move { Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[tokio::test]
    async fn it_names_the_platform_and_still_reverts_quietly() {
        let publisher = UnsupportedPublisher::new();
        let published = Published {
            interface: "tsundemo".into(),
            servers: vec!["10.0.0.1:5354".parse().unwrap()],
            domains: vec!["lab".into()],
        };
        let err = publisher.apply(&published).await.unwrap_err();
        assert!(matches!(err, PublishError::Unavailable(_)));
        assert!(err.to_string().contains(std::env::consts::OS));
        publisher.revert().await.unwrap();
    }
}
