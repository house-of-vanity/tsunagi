//! A minimal cancellation primitive.
//!
//! Kept local so the crate does not pull in a utility dependency for one type,
//! and so that no global state is involved: every agent and every network
//! runtime owns its own token.

use std::sync::Arc;

use tokio::sync::watch;

/// A clonable cancellation token.
#[derive(Debug, Clone)]
pub(crate) struct Shutdown {
    tx: Arc<watch::Sender<bool>>,
    rx: watch::Receiver<bool>,
}

impl Shutdown {
    /// Creates an untriggered token.
    pub(crate) fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            tx: Arc::new(tx),
            rx,
        }
    }

    /// Triggers cancellation. Idempotent.
    pub(crate) fn trigger(&self) {
        let _ = self.tx.send(true);
    }

    /// Whether cancellation has been triggered.
    pub(crate) fn is_triggered(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolves once cancellation has been triggered.
    pub(crate) async fn wait(&self) {
        let mut rx = self.rx.clone();
        {
            if *rx.borrow() {
                return;
            }
        }
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                return;
            }
        }
        // The sender is gone, which for our purposes means "stop".
    }
}
