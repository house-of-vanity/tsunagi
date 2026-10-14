//! Retry admission, shared by every connection to one remote endpoint.

use std::collections::VecDeque;

pub(super) const MAX_PENDING_OPEN_PATHS: usize = 64;

pub(super) fn queue_pending_open_path<T: Clone + Eq>(pending: &mut VecDeque<T>, path: &T) {
    if pending.contains(path) {
        return;
    }
    // Candidate churn must also stay bounded when every address is distinct.
    if pending.len() == MAX_PENDING_OPEN_PATHS {
        pending.pop_front();
    }
    pending.push_back(path.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_connection_failures_do_not_multiply_retry_work() {
        let mut pending = VecDeque::new();
        queue_pending_open_path(&mut pending, &1);
        for _ in 0..8 {
            // The actor takes the current queue and retries every path on
            // every live connection. Stock iroh multiplies it by four here.
            let batch = std::mem::take(&mut pending);
            for path in batch {
                for _ in 0..4 {
                    queue_pending_open_path(&mut pending, &path);
                }
            }
            assert_eq!(pending, VecDeque::from([1]));
        }
        // A later successful attempt leaves nothing queued.
        let batch = std::mem::take(&mut pending);
        assert_eq!(batch, VecDeque::from([1]));
        assert!(pending.is_empty());
    }

    #[test]
    fn unique_paths_stay_in_order_and_duplicates_do_not_evict_them() {
        let mut pending = VecDeque::new();
        for path in 0..MAX_PENDING_OPEN_PATHS {
            queue_pending_open_path(&mut pending, &path);
        }
        for _ in 0..100 {
            queue_pending_open_path(&mut pending, &0);
        }
        assert_eq!(
            pending,
            (0..MAX_PENDING_OPEN_PATHS).collect::<VecDeque<_>>()
        );
    }

    #[test]
    fn candidate_churn_evicts_oldest_and_keeps_retry_memory_bounded() {
        let mut pending = VecDeque::new();
        for path in 0..10_000 {
            queue_pending_open_path(&mut pending, &path);
            assert!(pending.len() <= MAX_PENDING_OPEN_PATHS);
            assert!(pending.capacity() <= MAX_PENDING_OPEN_PATHS);
        }
        assert_eq!(
            pending,
            (10_000 - MAX_PENDING_OPEN_PATHS..10_000).collect::<VecDeque<_>>()
        );
    }
}
