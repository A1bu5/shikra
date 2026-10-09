#![allow(unsafe_code)]

//! Killdate and working-hours policy shared by every transport.
//!
//! The builder bakes the values into the embedded configuration; `main` sets
//! them once at startup and the transport loops consult them before checking
//! in. Values are also reported to the teamserver at enrollment so operators
//! can see why an agent is quiet.

use std::sync::OnceLock;

#[derive(Clone, Debug, Default)]
pub struct Limits {
    /// Unix seconds after which the agent terminates (0 = never).
    pub killdate_unix: u64,
    /// Window in agent-local time, e.g. "9:00-17:00" (empty = always).
    pub working_hours: String,
}

static LIMITS: OnceLock<Limits> = OnceLock::new();

pub fn set(killdate_unix: u64, working_hours: String) {
    let _ = LIMITS.set(Limits {
        killdate_unix,
        working_hours: working_hours.trim().to_string(),
    });
}

pub fn get() -> &'static Limits {
    LIMITS.get_or_init(Limits::default)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

pub fn killdate_expired() -> bool {
    let killdate = get().killdate_unix;
    killdate > 0 && now_unix() >= killdate
}

/// True when a working-hours window is configured and the agent-local clock
/// is outside of it.
pub fn outside_working_hours() -> bool {
    let spec = get().working_hours.as_str();
    if spec.is_empty() {
        return false;
    }
    let Some((start, end)) = parse_window(spec) else {
        return false;
    };
    let (hour, minute) = local_hhmm();
    let now = hour * 60 + minute;
    if start <= end {
        now < start || now >= end
    } else {
        // Window crosses midnight, e.g. 22:00-06:00.
        now < start && now >= end
    }
}

fn parse_window(spec: &str) -> Option<(u32, u32)> {
    let (start, end) = spec.split_once('-')?;
    Some((parse_hhmm(start)?, parse_hhmm(end)?))
}

fn parse_hhmm(raw: &str) -> Option<u32> {
    let raw = raw.trim();
    let (hour, minute) = match raw.split_once(':') {
        Some((hour, minute)) => (hour.trim(), minute.trim()),
        None => (raw, "0"),
    };
    let hour: u32 = hour.parse().ok()?;
    let minute: u32 = minute.parse().ok()?;
    if hour > 23 || minute > 59 {
        return None;
    }
    Some(hour * 60 + minute)
}

#[cfg(unix)]
fn local_hhmm() -> (u32, u32) {
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&now, &mut tm);
        (tm.tm_hour as u32, tm.tm_min as u32)
    }
}

#[cfg(windows)]
fn local_hhmm() -> (u32, u32) {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    unsafe {
        let mut time: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut time);
        (time.wHour as u32, time.wMinute as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_parsing_handles_forms() {
        assert_eq!(parse_hhmm("9"), Some(540));
        assert_eq!(parse_hhmm("09:30"), Some(570));
        assert_eq!(parse_hhmm("bad"), None);
        assert_eq!(parse_window("9:00-17:00"), Some((540, 1020)));
    }
}
