#![allow(unsafe_code)]

//! Windows NetAPI enumeration (`net user`, `net share`, `net session`,
//! `net localgroup`) returning structured JSON.

use crate::TaskOutcome;

#[cfg(windows)]
mod imp {
    use super::*;
    use serde_json::json;
    use std::ffi::c_void;

    #[link(name = "netapi32")]
    unsafe extern "system" {
        fn NetUserEnum(
            server: *const u16,
            level: u32,
            filter: u32,
            buffer: *mut *mut u8,
            max_length: u32,
            read: *mut u32,
            total: *mut u32,
            resume: *mut u32,
        ) -> u32;
        fn NetShareEnum(
            server: *const u16,
            level: u32,
            buffer: *mut *mut u8,
            max_length: u32,
            read: *mut u32,
            total: *mut u32,
            resume: *mut u32,
        ) -> u32;
        fn NetSessionEnum(
            server: *const u16,
            client: *const u16,
            user: *const u16,
            level: u32,
            buffer: *mut *mut u8,
            max_length: u32,
            read: *mut u32,
            total: *mut u32,
            resume: *mut u32,
        ) -> u32;
        fn NetLocalGroupEnum(
            server: *const u16,
            level: u32,
            buffer: *mut *mut u8,
            max_length: u32,
            read: *mut u32,
            total: *mut u32,
            resume: *mut u32,
        ) -> u32;
        fn NetApiBufferFree(buffer: *const c_void) -> u32;
    }

    #[repr(C)]
    struct UserInfo0 {
        name: *const u16,
    }

    #[repr(C)]
    struct ShareInfo1 {
        netname: *const u16,
        share_type: u32,
        remark: *const u16,
    }

    #[repr(C)]
    struct SessionInfo10 {
        client: *const u16,
        username: *const u16,
        time: u32,
        idle_time: u32,
    }

    #[repr(C)]
    struct LocalGroupInfo0 {
        name: *const u16,
    }

    const MAX_PREFERRED_LENGTH: u32 = u32::MAX;
    const ERROR_MORE_DATA: u32 = 234;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe fn wide_to_string(pointer: *const u16) -> String {
        if pointer.is_null() {
            return String::new();
        }
        let mut length = 0usize;
        while unsafe { *pointer.add(length) } != 0 && length < 32 * 1024 {
            length += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(pointer, length) };
        String::from_utf16_lossy(slice)
    }

    unsafe fn collect<T>(
        mut call: impl FnMut(*mut *mut u8, *mut u32, *mut u32, *mut u32) -> u32,
        map: impl Fn(&T) -> serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, String> {
        let mut results = Vec::new();
        let mut resume = 0u32;
        loop {
            let mut buffer: *mut u8 = std::ptr::null_mut();
            let mut read = 0u32;
            let mut total = 0u32;
            let status = call(&mut buffer, &mut read, &mut total, &mut resume);
            if status != 0 && status != ERROR_MORE_DATA {
                if !buffer.is_null() {
                    unsafe { NetApiBufferFree(buffer as *const c_void) };
                }
                return Err(format!("NetAPI error {status}"));
            }
            if !buffer.is_null() {
                let entries =
                    unsafe { std::slice::from_raw_parts(buffer as *const T, read as usize) };
                for entry in entries {
                    results.push(map(entry));
                }
                unsafe { NetApiBufferFree(buffer as *const c_void) };
            }
            if status != ERROR_MORE_DATA {
                break;
            }
        }
        Ok(results)
    }

    pub fn task_net(args: &serde_json::Value) -> TaskOutcome {
        let action = args
            .get("action")
            .and_then(|value| value.as_str())
            .unwrap_or("users")
            .to_ascii_lowercase();
        let server = args
            .get("server")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty());
        let server_wide = server.map(wide);
        let server_ptr = server_wide
            .as_ref()
            .map(|value| value.as_ptr())
            .unwrap_or(std::ptr::null());

        let result = unsafe {
            match action.as_str() {
                "users" => collect(
                    |buffer, read, total, resume| {
                        NetUserEnum(
                            server_ptr,
                            0,
                            0,
                            buffer,
                            MAX_PREFERRED_LENGTH,
                            read,
                            total,
                            resume,
                        )
                    },
                    |entry: &UserInfo0| json!({ "name": wide_to_string(entry.name) }),
                ),
                "shares" => collect(
                    |buffer, read, total, resume| {
                        NetShareEnum(
                            server_ptr,
                            1,
                            buffer,
                            MAX_PREFERRED_LENGTH,
                            read,
                            total,
                            resume,
                        )
                    },
                    |entry: &ShareInfo1| {
                        json!({
                            "name": wide_to_string(entry.netname),
                            "type": entry.share_type,
                            "remark": wide_to_string(entry.remark),
                        })
                    },
                ),
                "sessions" => collect(
                    |buffer, read, total, resume| {
                        NetSessionEnum(
                            server_ptr,
                            std::ptr::null(),
                            std::ptr::null(),
                            10,
                            buffer,
                            MAX_PREFERRED_LENGTH,
                            read,
                            total,
                            resume,
                        )
                    },
                    |entry: &SessionInfo10| {
                        json!({
                            "client": wide_to_string(entry.client),
                            "user": wide_to_string(entry.username),
                            "active_secs": entry.time,
                            "idle_secs": entry.idle_time,
                        })
                    },
                ),
                "localgroups" => collect(
                    |buffer, read, total, resume| {
                        NetLocalGroupEnum(
                            server_ptr,
                            0,
                            buffer,
                            MAX_PREFERRED_LENGTH,
                            read,
                            total,
                            resume,
                        )
                    },
                    |entry: &LocalGroupInfo0| json!({ "name": wide_to_string(entry.name) }),
                ),
                other => {
                    return TaskOutcome::fail(format!(
                        "unsupported net action {other:?} (users, shares, sessions, localgroups)"
                    ))
                }
            }
        };

        match result {
            Ok(entries) => match serde_json::to_vec(&json!({
                "action": action,
                "server": server.unwrap_or("local"),
                "count": entries.len(),
                "entries": entries,
            })) {
                Ok(bytes) => TaskOutcome {
                    exit_code: 0,
                    stdout: bytes,
                    stderr: String::new(),
                },
                Err(err) => TaskOutcome::fail(format!("failed to encode net output: {err}")),
            },
            Err(err) => TaskOutcome::fail(err),
        }
    }
}

#[cfg(windows)]
pub use imp::task_net;

#[cfg(not(windows))]
pub fn task_net(_args: &serde_json::Value) -> TaskOutcome {
    TaskOutcome::fail("net enumeration is only supported on Windows")
}
