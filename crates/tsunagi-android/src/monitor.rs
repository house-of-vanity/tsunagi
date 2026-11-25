//! The GL thread holds a service subscription only while the inspector is visible.
use crate::service::{Outcome, Response};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::sync::oneshot::error::TryRecvError;
use tsunagi::traffic::TrafficSubscription;
use tsunagi_ui::monitor::Window;

pub(super) struct Monitor {
    pub view: Window,
    pending: Option<Response>,
    subscription: Option<TrafficSubscription>,
    next: Instant,
    failed: bool,
}
impl Monitor {
    pub fn new(cache: Option<PathBuf>) -> Self {
        Self {
            view: Window::new(cache),
            pending: None,
            subscription: None,
            next: Instant::now(),
            failed: false,
        }
    }
    pub fn pause(&mut self) {
        self.pending = None;
        self.subscription = None;
    }
    pub fn poll(&mut self, open: impl FnOnce() -> Result<Response, String>) {
        if self.failed {
            return;
        }
        if let Some(sub) = &self.subscription {
            if Instant::now() >= self.next {
                self.next = Instant::now() + Duration::from_secs(1);
                if !self.view.feed().sample(sub.snapshot()) {
                    self.pause();
                    self.failed = true;
                }
            }
            return;
        }
        let result = match &mut self.pending {
            Some(rx) => match rx.try_recv() {
                Ok(Ok(Outcome::Traffic(sub))) => {
                    // Time spent in the background must expire old rows before new traffic can refresh them.
                    self.view.feed().sample(Default::default());
                    self.subscription = Some(sub);
                    self.next = Instant::now() + Duration::from_secs(1);
                    self.pending = None;
                    return;
                }
                Ok(Err(e)) => Err(e),
                Err(TryRecvError::Empty) => return,
                _ => Err("Tsunagi Agent stopped".into()),
            },
            None => open().map(|r| self.pending = Some(r)),
        };
        if let Err(e) = result {
            self.pending = None;
            self.failed = true;
            self.view.feed().error(e);
        }
    }
}
