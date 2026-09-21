//! Stopping the tasks an agent started.
//!
//! Shutdown is cooperative first and bounded always: every loop watches a
//! cancellation token, and anything still running when its grace period ends
//! is aborted. Nothing an agent owns may outlive the agent, and no peer may
//! hold shutdown open by refusing to read.
//!
//! Public because a protocol crate spawns tasks of its own and is held to
//! the same rule: the agent gives each plugin a grace period, but abandoning
//! the future it is awaiting does not stop the task behind it.

use std::time::Duration;

use tokio::task::JoinHandle;

/// How long a task gets to notice cancellation before it is cut off.
///
/// Winding down is cooperative first: a task in the middle of a write to a
/// peer gets a moment to finish it. After that it is aborted, because a peer
/// that stops reading must not be able to hold shutdown open.
pub const TASK_GRACE: Duration = Duration::from_secs(5);

/// Waits for `task` to finish, aborting it if it outlasts `grace`.
///
/// Returns whether it finished on its own. `what` names it in the warning,
/// which is the only signal that something was cut off rather than stopped.
pub async fn wind_down(task: JoinHandle<()>, grace: Duration, what: &str) -> bool {
    let abort = task.abort_handle();
    if tokio::time::timeout(grace, task).await.is_err() {
        tracing::warn!(
            task = what,
            grace_secs = grace.as_secs_f32(),
            "task did not wind down in time; aborting it"
        );
        abort.abort();
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[tokio::test]
    async fn a_task_that_stops_on_its_own_is_not_aborted() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        let task = tokio::spawn(async move {
            tx.send(()).await.ok();
        });
        assert!(wind_down(task, Duration::from_secs(5), "cooperative").await);
        assert_eq!(rx.recv().await, Some(()), "it ran to completion");
    }

    #[tokio::test]
    async fn a_task_that_ignores_the_grace_is_aborted() {
        // A stand-in for a task blocked writing to a peer that stopped
        // reading: it will never finish by itself.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        let task = tokio::spawn(async move {
            let _held = tx;
            std::future::pending::<()>().await;
        });

        let finished = wind_down(task, Duration::from_millis(50), "wedged").await;
        assert!(!finished, "it had to be cut off");

        // Aborted for real: the task is gone, so what it held is dropped.
        let closed = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;
        assert_eq!(closed, Ok(None), "the aborted task dropped its sender");
    }
}
