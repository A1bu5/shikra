//! Per-key attempt limiter used to slow down enrollment and token guessing.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Sliding-window limiter: allows at most `max_attempts` attempts per
/// `window` for any given key (typically a peer address or token hash).
pub struct AttemptLimiter {
    max_attempts: usize,
    window: Duration,
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
}

impl AttemptLimiter {
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            max_attempts,
            window,
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Records an attempt and returns `false` when the key is over budget.
    pub async fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut attempts = self.attempts.lock().await;
        let entry = attempts.entry(key.to_string()).or_default();
        entry.retain(|at| now.duration_since(*at) < self.window);
        if entry.len() >= self.max_attempts {
            return false;
        }
        entry.push(now);
        // Opportunistically drop empty entries so the map cannot grow forever.
        if attempts.len() > 4096 {
            attempts.retain(|_, list| !list.is_empty());
        }
        true
    }

    /// Clears the budget for a key after a successful attempt.
    pub async fn reset(&self, key: &str) {
        self.attempts.lock().await.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blocks_after_budget() {
        let limiter = AttemptLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.check("peer").await);
        assert!(limiter.check("peer").await);
        assert!(limiter.check("peer").await);
        assert!(!limiter.check("peer").await);
        // Other keys are unaffected.
        assert!(limiter.check("other").await);
    }

    #[tokio::test]
    async fn reset_restores_budget() {
        let limiter = AttemptLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check("peer").await);
        assert!(!limiter.check("peer").await);
        limiter.reset("peer").await;
        assert!(limiter.check("peer").await);
    }

    #[tokio::test]
    async fn window_expiry_restores_budget() {
        let limiter = AttemptLimiter::new(1, Duration::from_millis(50));
        assert!(limiter.check("peer").await);
        assert!(!limiter.check("peer").await);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(limiter.check("peer").await);
    }
}
