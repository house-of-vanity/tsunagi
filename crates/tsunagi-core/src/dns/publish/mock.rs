//! A pretend resolver, so the wiring is tested without touching this host's.

use std::sync::{Arc, Mutex};

use crate::BoxFuture;

use super::{DnsPublisher, PublishError, Published};

/// Records what it was asked to do, and can be told to refuse.
#[derive(Debug, Clone, Default)]
pub struct MockPublisher {
    applied: Arc<Mutex<Option<Published>>>,
    failure: Option<PublishError>,
}

impl MockPublisher {
    /// A publisher that accepts everything.
    pub fn new() -> Self {
        Self::default()
    }

    /// A publisher that refuses everything, with this reason.
    pub fn failing(error: PublishError) -> Self {
        Self {
            applied: Arc::new(Mutex::new(None)),
            failure: Some(error),
        }
    }

    /// What is currently applied, if anything.
    pub fn applied(&self) -> Option<Published> {
        match self.applied.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl DnsPublisher for MockPublisher {
    fn name(&self) -> &str {
        "mock"
    }

    fn apply<'a>(&'a self, published: &'a Published) -> BoxFuture<'a, Result<(), PublishError>> {
        Box::pin(async move {
            if let Some(failure) = &self.failure {
                return Err(failure.clone());
            }
            match self.applied.lock() {
                Ok(mut guard) => *guard = Some(published.clone()),
                Err(poisoned) => *poisoned.into_inner() = Some(published.clone()),
            }
            Ok(())
        })
    }

    fn revert(&self) -> BoxFuture<'_, Result<(), PublishError>> {
        Box::pin(async move {
            match self.applied.lock() {
                Ok(mut guard) => *guard = None,
                Err(poisoned) => *poisoned.into_inner() = None,
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn published() -> Published {
        Published {
            interface: "tsundemo".into(),
            servers: vec![
                "10.13.37.69:5354".parse().unwrap(),
                "[::1]:5354".parse().unwrap(),
            ],
            domains: vec!["lab".into()],
        }
    }

    #[tokio::test]
    async fn applying_and_reverting_are_both_recorded() {
        let publisher = MockPublisher::new();
        assert!(publisher.applied().is_none());

        publisher.apply(&published()).await.unwrap();
        assert_eq!(publisher.applied(), Some(published()));

        publisher.revert().await.unwrap();
        assert!(publisher.applied().is_none());
        // Reverting twice is not an error: shutdown must not fail here.
        publisher.revert().await.unwrap();
    }

    #[tokio::test]
    async fn a_refusal_leaves_nothing_applied() {
        let publisher = MockPublisher::failing(PublishError::Refused("polkit said no".into()));
        assert!(publisher.apply(&published()).await.is_err());
        assert!(publisher.applied().is_none());
    }
}
