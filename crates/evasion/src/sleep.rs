//! Sleep helpers that prefer indirect syscalls on Windows.
//!
//! On Windows the blocking wait goes through `NtDelayExecution` so the call
//! does not traverse hooked `kernel32` wait APIs. On other platforms this is a
//! plain thread sleep.

use std::time::Duration;

/// Blocks the current thread for `duration`.
///
/// On Windows this attempts an indirect syscall sleep and falls back to
/// `std::thread::sleep` when ntdll cannot be parsed.
pub fn sleep(duration: Duration) {
    #[cfg(target_os = "windows")]
    {
        let millis = duration.as_millis().min(u64::MAX as u128) as u64;
        if crate::windows::syscall_sleep(millis).is_ok() {
            return;
        }
    }
    std::thread::sleep(duration);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_sleep_returns() {
        let start = std::time::Instant::now();
        sleep(Duration::from_millis(1));
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
